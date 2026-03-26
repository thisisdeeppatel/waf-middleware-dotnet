
namespace backend.Core.FirewallEngine;
    
    
public class WAFMiddleware : IMiddleware
{
    public Task InvokeAsync(HttpContext context, RequestDelegate next)
    {
        return next(context);
    }
}