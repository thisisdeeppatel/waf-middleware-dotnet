using Microsoft.Extensions.Options;

namespace backend.Core.FirewallEngine;

/// <summary>Assigns a 0–100 risk score and detects trusted / blocked bots from User-Agent (and partner flag).</summary>
public sealed class FirewallScoringEngine
{
    private readonly FirewallOptions _opt;

    public FirewallScoringEngine(IOptions<FirewallOptions> options) =>
        _opt = options.Value;

    public FirewallScoreSnapshot Evaluate(FirewallRequestDto dto)
    {
        var ua = dto.UserAgent ?? "";
        var factors = new List<string>(4);

        foreach (var bad in _opt.BotUserAgentBlacklistSubstrings)
        {
            if (string.IsNullOrEmpty(bad) || !ua.Contains(bad, StringComparison.OrdinalIgnoreCase))
                continue;
            factors.Add($"blacklisted_bot:{bad}");
            return new FirewallScoreSnapshot(100, TrustedBot: false, factors);
        }

        foreach (var good in _opt.BotUserAgentWhitelistSubstrings)
        {
            if (string.IsNullOrEmpty(good) || !ua.Contains(good, StringComparison.OrdinalIgnoreCase))
                continue;
            factors.Add($"whitelisted_bot:{good}");
            // Trusted bots bypass Redis rate limit; score is informational only.
            return new FirewallScoreSnapshot(0, TrustedBot: true, factors);
        }

        var score = 0;

        // Missing UA is weakly correlated with scripted clients; keep weight modest.
        if (string.IsNullOrWhiteSpace(ua))
        {
            score += 30;
            factors.Add("empty_user_agent");
        }

        if (dto.IsPartner)
        {
            factors.Add("partner_api_key");
            score = Math.Max(0, score - 25);
        }

        return new FirewallScoreSnapshot(Math.Clamp(score, 0, 100), TrustedBot: false, factors);
    }
}
