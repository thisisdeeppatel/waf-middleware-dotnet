using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using backend.Core.Connections;
using backend.Data;
using backend.Data.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace backend.Core.FirewallEngine;

public sealed class FirewallService
{
    private readonly RedisService _redis;
    private readonly FirewallOptions _opt;
    private readonly FirewallScoringEngine _scoring;
    private readonly IDbContextFactory<ApplicationDbContext> _dbFactory;
    private readonly ILogger<FirewallService> _logger;

    private const string BlockKeyPrefix = "waf:block:";
    private const string RateKeyPrefix = "waf:rl:";

    public FirewallService(
        IOptions<FirewallOptions> options,
        RedisService redis,
        FirewallScoringEngine scoring,
        IDbContextFactory<ApplicationDbContext> dbFactory,
        ILogger<FirewallService> logger)
    {
        _opt = options.Value;
        _redis = redis;
        _scoring = scoring;
        _dbFactory = dbFactory;
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
            await LogEnforcementAsync("Block", request, score, "redis_blocklist", clientId, cancellationToken);
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
            await LogEnforcementAsync("Block", request, score, reason, clientId, cancellationToken);
            return FirewallDecision.Block(reason);
        }

        var maxAllowed = request.IsPartner
            ? _opt.MaxRequestsPerWindowPartner
            : _opt.MaxRequestsPerWindowAnonymous;

        var requestsInWindow = await IncrementRequestCountInWindowAsync(clientId, request.IsPartner);
        if (requestsInWindow > maxAllowed)
        {
            await LogEnforcementAsync("Throttle", request, score, "rate_limited", clientId, cancellationToken);
            return FirewallDecision.Throttle("rate_limited", _opt.ThrottleRetryAfterSeconds);
        }

        return FirewallDecision.Allow();
    }

    private async Task LogEnforcementAsync(
        string kind,
        FirewallRequestDto dto,
        FirewallScoreSnapshot score,
        string reason,
        string signatureHash,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var audit = new FirewallAuditRecord(
            now,
            kind,
            dto.RemoteIp,
            dto.Path,
            reason,
            score.RiskScore,
            dto.UserAgent,
            score.Factors);

        try
        {
            await using var db = await _dbFactory.CreateDbContextAsync(cancellationToken);
            db.AccessLogs.Add(new AccessLog
            {
                Ip = dto.RemoteIp,
                UserAgent = dto.UserAgent ?? string.Empty,
                Path = dto.Path,
                RiskScore = score.RiskScore,
                Factors = JsonSerializer.Serialize(score.Factors),
                SignatureHash = signatureHash,
                CreatedAt = now,
                UpdatedAt = now
            });
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist AccessLog for firewall enforcement");
        }

        _logger.LogWarning(
            "Firewall {EnforcementKind} IP={RemoteIp} Path={Path} Reason={Reason} RiskScore={RiskScore} UserAgent={UserAgent} Factors={Factors}",
            audit.EnforcementKind,
            audit.RemoteIp,
            audit.Path,
            audit.Reason,
            audit.RiskScore,
            audit.UserAgent ?? "",
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
