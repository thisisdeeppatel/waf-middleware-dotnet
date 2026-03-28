namespace backend.Application.WAF.Dtos;

public class PagedAccessLogsResponse
{
    public IReadOnlyList<AccessLogEntryDto> Items { get; set; } = [];
    public int TotalCount { get; set; }
    public int Page { get; set; }
    public int PageSize { get; set; }
    public int TotalPages { get; set; }
}
