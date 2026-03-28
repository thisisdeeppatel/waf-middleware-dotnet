namespace backend.Application.WAF.Dtos;

public class AccessLogQueryParameters
{
    public DateTimeOffset? From { get; set; }
    public DateTimeOffset? To { get; set; }
    public string? Ip { get; set; }
    public string? Signature { get; set; }

    public string? UserAgent { get; set; }

    public int Page { get; set; } = 1;

    public int PageSize { get; set; } = 50;
}
