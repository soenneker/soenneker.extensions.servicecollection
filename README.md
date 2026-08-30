[![](https://img.shields.io/nuget/v/soenneker.extensions.servicecollection.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.servicecollection/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.servicecollection/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.servicecollection/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.extensions.servicecollection.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.servicecollection/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.servicecollection/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.servicecollection/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Extensions.ServiceCollection
Opinionated ASP.NET Core registration for JSON controllers, CORS, header API versioning, and Azure ARR client-certificate forwarding.

## Installation

```bash
dotnet add package Soenneker.Extensions.ServiceCollection
```

## Controller JSON options

```csharp
using Soenneker.Extensions.ServiceCollection;

services.AddControllersWithDefaultJsonOptions();
```

This registers MVC controllers and configures `System.Text.Json` to omit null properties when writing responses. It does not change null handling during deserialization.

## CORS policy

```json
{
  "CorsPolicy": {
    "Origins": "https://app.example.com;https://admin.example.com",
    "Methods": "GET,POST,PUT,DELETE"
  }
}
```

```csharp
services.AddDefaultCorsPolicy(configuration);

// Later in the request pipeline:
app.UseCors();
```

Origins are semicolon-separated; methods are comma-separated. Entries are trimmed and blanks are removed. Missing/empty origins or methods throw `InvalidOperationException` when the policy is built rather than opening access silently. Set either value to the single entry `*` only when unrestricted origins or methods are intentional.

The policy always allows any request header. Passing `signalR: true` enables credentials and therefore requires explicit origins; `*` is rejected. CORS is a browser access policy, not authentication or authorization.

## Header API versioning

```csharp
services.ConfigureVersioning();
```

This registers API versioning with version `1.0` as the default, reads the requested version from the `api-version` header, and assumes the default when the header is absent. It does not add URL-segment or query-string version readers and does not report supported versions in response headers.

## Azure ARR certificate forwarding

```csharp
services.AddArrClientCertForwarding();

// Before authentication/authorization:
app.UseCertificateForwarding();
```

The default header is `X-ARR-ClientCert`; pass another name when the trusted proxy uses a different header. The value must be a base64-encoded DER certificate. Blank, malformed, or empty values produce no certificate; invalid certificate bytes can throw during certificate loading.

Certificate headers are spoofable when accepted directly from clients. Use this only behind a trusted proxy that removes incoming copies of the header and writes its own verified value. Certificate forwarding parses a certificate; it does not establish trust, validate a chain, or authenticate the request by itself.

All methods register services only. The corresponding middleware and endpoint mapping remain the application's responsibility.
