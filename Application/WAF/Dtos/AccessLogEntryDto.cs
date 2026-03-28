namespace backend.Application.WAF.Dtos;

public class AccessLogEntryDto
{
    public long Id { get; set; }
    public string? Ip { get; set; }
    public string UserAgent { get; set; } = "";
    public string Path { get; set; } = "";
    public int RiskScore { get; set; }
    public string Factors { get; set; } = "";
    public string SignatureHash { get; set; } = "";
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
}
