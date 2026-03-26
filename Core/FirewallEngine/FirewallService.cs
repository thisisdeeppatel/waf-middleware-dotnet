using System.Security.Cryptography;
using System.Text;
using backend.Core.Connections;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace backend.Core.FirewallEngine;

public sealed class FirewallService
{
    private readonly RedisService _redis;
    private readonly FirewallOptions _opt;
    private readonly FirewallScoringEngine _scoring;
    private readonly ILogger<FirewallService> _logger;

    private const string BlockKeyPrefix = "waf:block:";
    private const string RateKeyPrefix = "waf:rl:";

    public FirewallService(
        IOptions<FirewallOptions> options,
        RedisService redis,
        FirewallScoringEngine scoring,
        ILogger<FirewallService> logger)
    {
        _opt = options.Value;
        _redis = redis;
        _scoring = scoring;
        _logger = logger;
    }

    // Raw string shape (order + '|') feeds blocklist keys; rate limits append :p / :a so partner vs anonymous do not share counters.
    public string GenerateFingerprint(FirewallRequestDto request)
    {
        var raw = $"{request.RemoteIp}|{request.UserAgent}|{request.Accept}|{request.AcceptEncoding}";

        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(raw));

        return Convert.ToHexString(hash);
    }

    public async Task<FirewallDecision> GetImmediateDecisionAsync(
        FirewallRequestDto request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // One evaluation per request: drives threshold block + logging; cheap string work only.
        var score = _scoring.Evaluate(request);

        var clientId = GenerateFingerprint(request);

        // Ops-controlled deny — still evaluated before trusted-bot bypass so you can override crawlers if needed.
        if (await IsOnBlocklistAsync(clientId))
        {
            LogEnforcement("Block", request, score, "redis_blocklist");
            return FirewallDecision.Block("redis_blocklist");
        }

        // Known-good crawlers / partner bots: no Redis rate counter (saves noise and Redis budget).
        if (score.TrustedBot)
            return FirewallDecision.Allow();

        if (score.RiskScore >= _opt.RiskScoreBlockThreshold)
        {
            var reason = score.Factors.Any(f => f.StartsWith("blacklisted_bot:", StringComparison.Ordinal))
                ? "blacklisted_bot"
                : "risk_score";
            LogEnforcement("Block", request, score, reason);
            return FirewallDecision.Block(reason);
        }

        var maxAllowed = request.IsPartner
            ? _opt.MaxRequestsPerWindowPartner
            : _opt.MaxRequestsPerWindowAnonymous;

        var requestsInWindow = await IncrementRequestCountInWindowAsync(clientId, request.IsPartner);
        if (requestsInWindow > maxAllowed)
        {
            LogEnforcement("Throttle", request, score, "rate_limited");
            return FirewallDecision.Throttle("rate_limited", _opt.ThrottleRetryAfterSeconds);
        }

        return FirewallDecision.Allow();
    }

    private void LogEnforcement(string kind, FirewallRequestDto dto, FirewallScoreSnapshot score, string reason)
    {
        // Immutable snapshot: append-only DB row can mirror this 1:1 later.
        var audit = new FirewallAuditRecord(
            DateTimeOffset.UtcNow,
            kind,
            dto.RemoteIp,
            dto.Path,
            reason,
            score.RiskScore,
            dto.UserAgent,
            score.Factors);

        _logger.LogWarning(
            "Firewall {EnforcementKind} IP={RemoteIp} Path={Path} Reason={Reason} RiskScore={RiskScore} Factors={Factors}",
            audit.EnforcementKind,
            audit.RemoteIp,
            audit.Path,
            audit.Reason,
            audit.RiskScore,
            string.Join(',', audit.ScoreFactors));
    }

    private Task<bool> IsOnBlocklistAsync(string clientId) =>
        _redis.KeyExistsAsync($"{BlockKeyPrefix}{clientId}");

    // Partner vs anonymous share the same blocklist fingerprint but must not share rate-limit buckets
    // (different thresholds; otherwise one tier exhausts the shared counter for the other).
    private Task<long> IncrementRequestCountInWindowAsync(string clientId, bool isPartner)
    {
        var window = _opt.RateWindow > TimeSpan.Zero
            ? _opt.RateWindow
            : TimeSpan.FromMinutes(1);
        var tier = isPartner ? "p" : "a";
        return _redis.StringIncrementAsync($"{RateKeyPrefix}{clientId}:{tier}", window);
    }
}
