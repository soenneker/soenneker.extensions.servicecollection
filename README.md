[![](https://img.shields.io/nuget/v/soenneker.extensions.servicecollection.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.servicecollection/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.servicecollection/publish-package.yml?style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.servicecollection/actions/workflows/publish-package.yml)
[![](https://img.shields.io/nuget/dt/soenneker.extensions.servicecollection.svg?style=for-the-badge)](https://www.nuget.org/packages/soenneker.extensions.servicecollection/)
[![](https://img.shields.io/github/actions/workflow/status/soenneker/soenneker.extensions.servicecollection/codeql.yml?label=CodeQL&style=for-the-badge)](https://github.com/soenneker/soenneker.extensions.servicecollection/actions/workflows/codeql.yml)

# ![](https://user-images.githubusercontent.com/4441470/224455560-91ed3ee7-f510-4041-a8d2-3fc093025112.png) Soenneker.Extensions.ServiceCollection
A collection of helpful IServiceCollection extension methods.

## Installation

```bash
dotnet add package Soenneker.Extensions.ServiceCollection
```

## Quick start

```csharp
using Soenneker.Extensions.ServiceCollection;

// Given an existing IServiceCollection named services:
services.AddControllersWithDefaultJsonOptions();
```

## Common operations

- `AddControllersWithDefaultJsonOptions()` - Adds json serializer options.
- `AddDefaultCorsPolicy()` - Adds default cors policy.
- `ConfigureVersioning()` - Configures versioning.
- `AddArrClientCertForwarding()` - Adds certificate forwarding that reads a base64-encoded DER cert from a header (default: "X-ARR-ClientCert").
