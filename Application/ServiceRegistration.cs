using Microsoft.Extensions.DependencyInjection;

namespace backend.Application;

public static class ServiceRegistration
{
    public static IServiceCollection AddApplicationServices(this IServiceCollection services)
    {
        //services.AddSingleton<Todo.TodoService>();
        services.AddSingleton<Auth.AuthService>();
        
        return services;
    }
}

