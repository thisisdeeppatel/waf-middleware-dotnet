namespace backend.Core.FirewallEngine;

/// <summary>All WAF tunables in one place; bind from configuration or set in <c>Configure&lt;FirewallOptions&gt;</c>.</summary>
public sealed class FirewallOptions
{
    public const string SectionName = "Firewall";

    /// <summary>First segment(s) match; those requests skip the firewall (fully public).</summary>
    public List<string> ExemptPathPrefixes { get; set; } =
        ["/health", "/openapi", "/swagger", "/favicon.ico"];

    public string PartnerApiKeyHeaderName { get; set; } = "X-Partner-Api-Key";

    /// <summary>Requests presenting one of these values in <see cref="PartnerApiKeyHeaderName"/> use partner rate limits.</summary>
    public List<string> PartnerApiKeys { get; set; } = [];

    public TimeSpan RateWindow { get; set; } = TimeSpan.FromMinutes(1);

    public int MaxRequestsPerWindowAnonymous { get; set; } = 300;

    public int MaxRequestsPerWindowPartner { get; set; } = 3000;

    public int ThrottleRetryAfterSeconds { get; set; } = 60;

    /// <summary>Substring match, case-insensitive. Matched clients skip Redis rate limiting (still honor Redis block + scoring block).</summary>
    public List<string> BotUserAgentWhitelistSubstrings { get; set; } =
    [
        "Googlebot",
        "Google-InspectionTool",
        "bingbot",
        "Slurp",
        "GPTBot",
        "ChatGPT-User",
        "OAI-SearchBot",
        "OpenAI-SearchBot"
    ];

    /// <summary>Substring match, case-insensitive. Immediate block when matched (unless Redis allow is the only override—there is none; Redis block wins first).</summary>
    public List<string> BotUserAgentBlacklistSubstrings { get; set; } = [];

    /// <summary>Risk score is 0 (calm) to 100 (severe). At or above → hard block (after Redis ops block, after trusted-bot short-circuit).</summary>
    public int RiskScoreBlockThreshold { get; set; } = 75;
}
