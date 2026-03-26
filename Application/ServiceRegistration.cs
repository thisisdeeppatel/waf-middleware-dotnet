using backend.Core.FirewallEngine;
using Microsoft.Extensions.DependencyInjection;

namespace backend.Application;

public static class ServiceRegistration
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        services.AddSingleton<FirewallService>();
        services.AddScoped<Auth.AuthService>();

        return services;
    }
}

