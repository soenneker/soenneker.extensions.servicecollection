using System.Text.Json.Serialization;
using Asp.Versioning;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Soenneker.Extensions.String;

namespace Soenneker.Extensions.ServiceCollection;

/// <summary>
/// A collection of helpful IServiceCollection extension methods
/// </summary>
public static class ServiceCollectionsExtension
{
    /// <summary>
    /// Adds json serializer options
    /// </summary>
    public static void AddControllersWithDefaultJsonOptions(this IServiceCollection services)
    {
        services.AddControllers()
                .AddJsonOptions(jsonOptions => { jsonOptions.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull; });
    }

    public static void AddDefaultCorsPolicy(this IServiceCollection services, IConfiguration configuration, bool signalR = false)
    {
        services.AddCors(options =>
        {
            options.AddDefaultPolicy(builder =>
            {
                var origins = configuration.GetValue<string>("CorsPolicy:Origins");
                var methods = configuration.GetValue<string>("CorsPolicy:Methods");

                if (origins.HasContent())
                    builder.WithOrigins(origins.Split(';'));
                else
                {
                    Log.Error("CorsPolicy Origins was null, allowing any origin (insecure!)");
                    builder.AllowAnyOrigin();
                }

                if (methods.HasContent())
                    builder.WithMethods(methods.Split(","));
                else
                {
                    Log.Error("CorsPolicy Methods was null, allowing any method types (insecure!)");
                    builder.AllowAnyMethod();
                }

                if (signalR)
                    builder.AllowCredentials();

                builder.AllowAnyHeader();
            });
        });
    }

    public static void ConfigureVersioning(this IServiceCollection services)
    {
        services.AddApiVersioning(o =>
            {
                o.DefaultApiVersion = new ApiVersion(1, 0);
                o.ApiVersionReader = new HeaderApiVersionReader("api-version");
                o.AssumeDefaultVersionWhenUnspecified = true;
            }
        );
    }
}