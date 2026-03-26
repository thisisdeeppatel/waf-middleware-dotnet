namespace backend.Core.FirewallEngine;

public sealed record FirewallRequestDto(
    string Path,
    string? RemoteIp,
    string UserAgent,
    string Accept,
    string AcceptEncoding,
    bool IsPartner);

public sealed record FirewallScoreSnapshot(int RiskScore, bool TrustedBot, IReadOnlyList<string> Factors);

/// <summary>Row-shaped audit payload for structured logs; can be persisted to a table later without redesign.</summary>
public sealed record FirewallAuditRecord(
    DateTimeOffset TimestampUtc,
    string EnforcementKind,
    string? RemoteIp,
    string Path,
    string Reason,
    int RiskScore,
    string UserAgent,
    IReadOnlyList<string> ScoreFactors);

public enum BotAction
{
    Allow,
    Block,
    Throttle
}

public readonly struct FirewallDecision
{
    public BotAction Action { get; init; }
    public string Reason { get; init; }
    public int RetryAfterSeconds { get; init; }

    public static FirewallDecision Allow() => new() { Action = BotAction.Allow };

    public static FirewallDecision Block(string reason) =>
        new() { Action = BotAction.Block, Reason = reason };

    public static FirewallDecision Throttle(string reason, int retryAfterSeconds) =>
        new()
        {
            Action = BotAction.Throttle,
            Reason = reason,
            RetryAfterSeconds = retryAfterSeconds
        };
}
