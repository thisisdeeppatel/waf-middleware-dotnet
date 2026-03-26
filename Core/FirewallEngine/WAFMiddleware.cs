using System.Net;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace backend.Core.FirewallEngine;

public sealed class WAFMiddleware : IMiddleware
{
    private readonly FirewallService _firewall;
    private readonly IOptions<FirewallOptions> _options;

    public WAFMiddleware(FirewallService firewall, IOptions<FirewallOptions> options)
    {
        _firewall = firewall;
        _options = options;
    }

    public async Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        if (IsExemptPath(context.Request.Path))
        {
            await next(context);
            return;
        }

        var dto = CreateRequestDto(context);
        var decision = await _firewall.GetImmediateDecisionAsync(dto, context.RequestAborted);

        if (decision.Action == BotAction.Allow)
        {
            await next(context);
            return;
        }

        // Rejection short-circuit: never call next — auth, controllers, and downstream middleware must not run.
        await WriteRejectionAsync(context.Response, decision, context.RequestAborted);
    }

    private bool IsExemptPath(PathString path)
    {
        foreach (var prefix in _options.Value.ExemptPathPrefixes)
        {
            if (string.IsNullOrWhiteSpace(prefix))
                continue;
            if (path.StartsWithSegments(prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    // Values + order feed FirewallService.GenerateFingerprint; mismatch breaks fingerprint ↔ Redis ops tooling.
    private FirewallRequestDto CreateRequestDto(HttpContext context)
    {
        var opt = _options.Value;
        var headers = context.Request.Headers;
        var presented = headers[opt.PartnerApiKeyHeaderName].ToString().Trim();
        var isPartner = !string.IsNullOrEmpty(presented)
            && opt.PartnerApiKeys.Exists(k =>
            {
                var key = k.Trim();
                return key.Length > 0 && key == presented;
            });

        return new FirewallRequestDto(
            context.Request.Path.Value ?? "",
            context.Connection.RemoteIpAddress?.ToString(),
            headers["User-Agent"].ToString(),
            headers["Accept"].ToString(),
            headers["Accept-Encoding"].ToString(),
            isPartner);
    }

    // ASCII bodies only here: ContentLength must equal the exact byte length written.
    private static async Task WriteRejectionAsync(
        HttpResponse response,
        FirewallDecision decision,
        CancellationToken cancellationToken)
    {
        switch (decision.Action)
        {
            case BotAction.Block:
                response.StatusCode = (int)HttpStatusCode.Forbidden;
                response.ContentLength = 9;
                await response.WriteAsync("Forbidden", cancellationToken);
                return;

            case BotAction.Throttle:
                response.StatusCode = (int)HttpStatusCode.TooManyRequests;
                response.Headers.RetryAfter = decision.RetryAfterSeconds.ToString();
                response.ContentLength = 17;
                await response.WriteAsync("Too Many Requests", cancellationToken);
                return;

            default:
                throw new InvalidOperationException($"Unexpected action {decision.Action}");
        }
    }
}
