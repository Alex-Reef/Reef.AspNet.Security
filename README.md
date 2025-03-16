# Reef.AspNet.Security

**Reef.AspNet.Security** is a library for authentication and authorization in ASP.NET Core using JWT.

## 📌 Features
- JWT token generation
- Token validation
- Refresh token support
- Configurable settings

## 🚀 Installation
Since the library is not available on NuGet, you need to add it manually.

1. Copy `Reef.AspNet.Security.dll` into your project.
2. Add a reference to the DLL in your project.

## ⚙️ Usage
### 1. Adding Security Service in `Program.cs`
```csharp
using Reef.AspNet.Security;
using Reef.AspNet.Security.Configuration;
using Reef.AspNet.Security.DI;

var builder = WebApplication.CreateBuilder(args);

var jwtConfig = builder.Configuration.GetSection("JwtConfiguration").Get<JwtConfiguration>()
    ?? throw new InvalidOperationException("JWT configuration is missing");

builder.AddSecurity(jwtConfig);

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();
app.Run();
```

### 2. Generating a Token
```csharp
using System.Security.Claims;
using Microsoft.Extensions.DependencyInjection;
using Reef.AspNet.Security;

var jwtService = serviceProvider.GetRequiredService<IJwtService>();
var claims = new List<Claim>
{
    new Claim(ClaimTypes.Name, "JohnDoe"),
    new Claim(ClaimTypes.Role, "Admin")
};

string token = jwtService.GenerateToken(claims);
Console.WriteLine($"Generated Token: {token}");
```

### 3. Extracting Data from Token
```csharp
var claims = jwtService.GetClaimsFromToken(token);
foreach (var claim in claims)
{
    Console.WriteLine($"{claim.Type}: {claim.Value}");
}
```

## 🛠 Configuration
The `JwtConfiguration` class includes the following settings:
- **Secret** - Secret key for signing the token (minimum 16 characters).
- **Issuer** - Token issuer.
- **Audience** - Token audience.
- **AccessTokenExpiration** - Token expiration time in seconds.

## 📜 License
This project is licensed under the Apache License 2.0 License.

## 📧 Contact
If you have any questions or suggestions, create an issue or contact me via GitHub.
