using backend.Application.WAF.Dtos;
using backend.Data;
using backend.Data.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace backend.Application.WAF;

[ApiController]
[Route("api/access-logs")]
//[Authorize]
public class AccessLogsController : ControllerBase
{
    private const int MaxPageSize = 200;

    private readonly ApplicationDbContext _db;

    public AccessLogsController(ApplicationDbContext db)
    {
        _db = db;
    }

    /// <summary>
    /// Lists access log entries with optional filters and pagination.
    /// </summary>
    [HttpGet]
    public async Task<ActionResult<PagedAccessLogsResponse>> List([FromQuery] AccessLogQueryParameters query, CancellationToken cancellationToken)
    {
        if (query.Page < 1)
        {
            return BadRequest("Page must be at least 1.");
        }

        if (query.PageSize < 1)
        {
            return BadRequest("PageSize must be at least 1.");
        }

        var pageSize = Math.Min(query.PageSize, MaxPageSize);

        IQueryable<AccessLog> q = _db.AccessLogs.AsNoTracking();

        if (query.From is { } from)
        {
            // Npgsql only accepts UTC offsets for timestamptz parameters; bound dates are often local midnight.
            var fromUtc = from.ToUniversalTime();
            q = q.Where(x => x.CreatedAt >= fromUtc);
        }

        if (query.To is { } to)
        {
            var toUtc = to.ToUniversalTime();
            q = q.Where(x => x.CreatedAt <= toUtc);
        }

        if (!string.IsNullOrWhiteSpace(query.Ip))
        {
            var ip = query.Ip.Trim();
            q = q.Where(x => x.Ip != null && x.Ip.Contains(ip));
        }

        if (!string.IsNullOrWhiteSpace(query.Signature))
        {
            var sig = query.Signature.Trim();
            q = q.Where(x => x.SignatureHash.Contains(sig));
        }

        if (!string.IsNullOrWhiteSpace(query.UserAgent))
        {
            var ua = query.UserAgent.Trim();
            q = q.Where(x => x.UserAgent.Contains(ua));
        }

        var totalCount = await q.CountAsync(cancellationToken);
        var totalPages = totalCount == 0 ? 0 : (int)Math.Ceiling(totalCount / (double)pageSize);

        var items = await q
            .OrderByDescending(x => x.CreatedAt)
            .Skip((query.Page - 1) * pageSize)
            .Take(pageSize)
            .Select(x => new AccessLogEntryDto
            {
                Id = x.Id,
                Ip = x.Ip,
                UserAgent = x.UserAgent,
                Path = x.Path,
                RiskScore = x.RiskScore,
                Factors = x.Factors,
                SignatureHash = x.SignatureHash,
                CreatedAt = x.CreatedAt,
                UpdatedAt = x.UpdatedAt
            })
            .ToListAsync(cancellationToken);

        return Ok(new PagedAccessLogsResponse
        {
            Items = items,
            TotalCount = totalCount,
            Page = query.Page,
            PageSize = pageSize,
            TotalPages = totalPages
        });
    }
}
