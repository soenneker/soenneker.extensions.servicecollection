using System.Text.Json.Serialization;
using Microsoft.Extensions.DependencyInjection;

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
        services.AddControllers().AddJsonOptions(jsonOptions => { jsonOptions.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull; });
    }
}
