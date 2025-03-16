using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Reef.AspNet.Security.Configuration;
using System.Text;

namespace Reef.AspNet.Security.DI
{
	public static partial class ServiceBuilder
	{
		public static WebApplicationBuilder AddSecurity(this WebApplicationBuilder builder, JwtConfiguration jwtConfig)
		{
			builder.Services
				.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
				.AddJwtBearer(options =>
				{
					options.RequireHttpsMetadata = false;
					options.SaveToken = true;

					options.TokenValidationParameters = new TokenValidationParameters
					{
						ValidateIssuer = true,
						ValidIssuer = jwtConfig.Issuer,
						ValidateAudience = true,
						ValidAudience = jwtConfig.Audience,
						ValidateLifetime = true,
						ValidateIssuerSigningKey = true,
						IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig.Secret))
					};

					options.Events = new JwtBearerEvents
					{
						OnForbidden = context =>
						{
							context.Response.StatusCode = StatusCodes.Status403Forbidden;
							context.Response.ContentType = "application/json";
							return context.Response.WriteAsync("{\"error\": \"Forbidden: You do not have access.\"}");
						}
					};
				});

			builder.Services.AddAuthorization();

			builder.Services.AddSingleton(jwtConfig);
			builder.Services.AddScoped<IJwtService, JwtService>();

			return builder;
		}
	}
}
