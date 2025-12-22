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
    private const string _defaultArrClientCertHeader = "X-ARR-ClientCert";
    private const string _apiVersionHeaderName = "api-version";

    /// <summary>
    /// Adds json serializer options
    /// </summary>
    public static void AddControllersWithDefaultJsonOptions(this IServiceCollection services)
    {
        services.AddControllers()
                .AddJsonOptions(jsonOptions =>
                {
                    jsonOptions.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
                });
    }

    public static void AddDefaultCorsPolicy(this IServiceCollection services, IConfiguration configuration, bool signalR = false)
    {
        var originsRaw = configuration.GetValue<string?>("CorsPolicy:Origins");
        var methodsRaw = configuration.GetValue<string?>("CorsPolicy:Methods");

        string[]? originArray = originsRaw?.SplitTrimmedNonEmpty(';');
        string[]? methodArray = methodsRaw?.SplitTrimmedNonEmpty(',');

        services.AddCors(options =>
        {
            options.AddDefaultPolicy(builder =>
            {
                bool hasOrigins = originArray is { Length: > 0 };
                bool hasMethods = methodArray is { Length: > 0 };

                if (signalR)
                {
                    // SignalR + credentials requires explicit origins (no AllowAnyOrigin).
                    if (!hasOrigins)
                        throw new InvalidOperationException("CorsPolicy:Origins must be configured when signalR=true (credentials require explicit origins).");

                    builder.WithOrigins(originArray!)
                           .AllowCredentials();
                }
                else
                {
                    if (hasOrigins)
                        builder.WithOrigins(originArray!);
                    else
                    {
                        Log.Error("CorsPolicy Origins missing/empty after parsing, allowing any origin (insecure!)");
                        builder.AllowAnyOrigin();
                    }
                }

                if (hasMethods)
                    builder.WithMethods(methodArray!);
                else
                {
                    Log.Error("CorsPolicy Methods missing/empty after parsing, allowing any method types (insecure!)");
                    builder.AllowAnyMethod();
                }

                builder.AllowAnyHeader();
            });
        });
    }

    public static void ConfigureVersioning(this IServiceCollection services)
    {
        services.AddApiVersioning(o =>
        {
            o.DefaultApiVersion = new ApiVersion(1, 0);
            o.ApiVersionReader = new HeaderApiVersionReader(_apiVersionHeaderName);
            o.AssumeDefaultVersionWhenUnspecified = true;
        });
    }

    /// <summary>
    /// Adds certificate forwarding that reads a base64-encoded DER cert from a header (default: "X-ARR-ClientCert").
    /// </summary>
    public static IServiceCollection AddArrClientCertForwarding(this IServiceCollection services, string headerName = _defaultArrClientCertHeader)
    {
        return services.AddCertificateForwarding(o =>
        {
            o.CertificateHeader = headerName;

            o.HeaderConverter = static headerValue =>
            {
                if (headerValue.IsNullOrWhiteSpace())
                    return null;

                // Exact-ish max decoded length:
                // (len/4)*3 minus padding (0..2). Handles typical "=" / "==" endings.
                int len = headerValue.Length;
                int padding = len != 0 && headerValue[len - 1] == '='
                    ? len > 1 && headerValue[len - 2] == '=' ? 2 : 1
                    : 0;

                int maxDecoded = len / 4 * 3 - padding;
                if (maxDecoded <= 0)
                    return null;

                byte[] rented = ArrayPool<byte>.Shared.Rent(maxDecoded);

                try
                {
                    if (!Convert.TryFromBase64String(headerValue, rented, out int written) || written <= 0)
                        return null;

                    return X509CertificateLoader.LoadCertificate(rented.AsSpan(0, written));
                }
                finally
                {
                    ArrayPool<byte>.Shared.Return(rented);
                }
            };
        });
    }
}