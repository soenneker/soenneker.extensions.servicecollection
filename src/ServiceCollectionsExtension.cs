using Asp.Versioning;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using Soenneker.Extensions.String;
using System;
using System.Buffers;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Serialization;

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
        });
    }

    /// <summary>
    /// Adds certificate forwarding that reads a base64-encoded DER cert from a header (default: "X-ARR-ClientCert").
    /// </summary>
    public static IServiceCollection AddArrClientCertForwarding(this IServiceCollection services, string headerName = "X-ARR-ClientCert")
    {
        return services.AddCertificateForwarding(o =>
        {
            o.CertificateHeader = headerName;
            o.HeaderConverter = headerValue =>
            {
                if (headerValue.IsNullOrWhiteSpace())
                    return null!;

                int max = checked(headerValue.Length * 3 / 4);
                byte[] rented = ArrayPool<byte>.Shared.Rent(max);

                try
                {
                    if (!Convert.TryFromBase64String(headerValue, rented, out int _))
                        return null!;

                    return X509CertificateLoader.LoadCertificate(rented);
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            };
        });
    }
}