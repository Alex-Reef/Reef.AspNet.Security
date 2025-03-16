using Microsoft.IdentityModel.Tokens;
using Reef.AspNet.Security.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Reef.AspNet.Security
{
	/// <summary>
	/// Service for working with JWT tokens and refresh tokens.
	/// </summary>
	public class JwtService : IJwtService
	{
		private readonly JwtConfiguration _jwtConfiguration;
		private readonly JwtSecurityTokenHandler _tokenHandler = new();

		public JwtService(JwtConfiguration jwtConfiguration)
		{
			_jwtConfiguration = jwtConfiguration ?? throw new ArgumentNullException(nameof(jwtConfiguration));
		}

		/// <summary>
		/// Generates a random refresh token.
		/// </summary>
		/// <returns>A Base64 string representing the refresh token.</returns>
		public string GenerateRefreshToken()
		{
			var randomNumber = new byte[32];
			using var rng = RandomNumberGenerator.Create();
			rng.GetBytes(randomNumber);
			return Convert.ToBase64String(randomNumber);
		}

		/// <summary>
		/// Generates a JWT token based on the provided claims.
		/// </summary>
		/// <param name="claims">List of claims to include in the token.</param>
		/// <returns>A serialized JWT token.</returns>
		/// <exception cref="ArgumentException">If claims are null or empty, or if the secret key is too short.</exception>
		public string GenerateToken(List<Claim> claims)
		{
			if (claims == null || !claims.Any())
				throw new ArgumentException("Claims cannot be null or empty.", nameof(claims));

			var secretBytes = Encoding.UTF8.GetBytes(_jwtConfiguration.Secret);
			if (secretBytes.Length < 16)
				throw new ArgumentException("JWT secret must be at least 16 bytes long.", nameof(_jwtConfiguration.Secret));

			var authSigningKey = new SymmetricSecurityKey(secretBytes);

			var tokenDescriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(claims),
				Expires = DateTime.UtcNow.AddSeconds(_jwtConfiguration.AccessTokenExpiration).ToUniversalTime(),
				Issuer = _jwtConfiguration.Issuer,
				Audience = _jwtConfiguration.Audience,
				SigningCredentials = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
			};

			var token = _tokenHandler.CreateToken(tokenDescriptor);
			return _tokenHandler.WriteToken(token);
		}

		/// <summary>
		/// Extracts the ClaimsPrincipal from an expired JWT token.
		/// </summary>
		/// <param name="token">The JWT token to validate.</param>
		/// <returns>A ClaimsPrincipal containing the token's claims.</returns>
		/// <exception cref="ArgumentException">If the token is null or empty.</exception>
		/// <exception cref="SecurityTokenException">If the token is invalid.</exception>
		public ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
		{
			if (string.IsNullOrWhiteSpace(token))
				throw new ArgumentException("Token cannot be null or empty.", nameof(token));

			var tokenValidationParameters = new TokenValidationParameters
			{
				ValidateAudience = false,
				ValidateIssuer = false,
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.Secret)),
				ValidateLifetime = false
			};

			var principal = _tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
			if (securityToken is not JwtSecurityToken jwtSecurityToken ||
				!jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
				throw new SecurityTokenException("Invalid token");

			return principal;
		}

		/// <summary>
		/// Extracts a list of all claims from a JWT token.
		/// </summary>
		/// <param name="token">The JWT token to analyze.</param>
		/// <param name="validateLifetime">Indicates whether to validate the token's lifetime.</param>
		/// <returns>A list of claims from the token.</returns>
		/// <exception cref="ArgumentException">If the token is null or empty.</exception>
		/// <exception cref="SecurityTokenException">If the token is invalid.</exception>
		public List<Claim> GetClaimsFromToken(string token, bool validateLifetime = true)
		{
			if (string.IsNullOrWhiteSpace(token))
				throw new ArgumentException("Token cannot be null or empty.", nameof(token));

			var tokenValidationParameters = new TokenValidationParameters
			{
				ValidateAudience = true,
				ValidAudience = _jwtConfiguration.Audience,
				ValidateIssuer = true,
				ValidIssuer = _jwtConfiguration.Issuer,
				ValidateIssuerSigningKey = true,
				IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtConfiguration.Secret)),
				ValidateLifetime = validateLifetime // By default, validate lifetime
			};

			var principal = _tokenHandler.ValidateToken(token, tokenValidationParameters, out var securityToken);
			if (securityToken is not JwtSecurityToken jwtSecurityToken ||
				!jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
				throw new SecurityTokenException("Invalid token");

			return principal.Claims.ToList();
		}

		/// <summary>
		/// Extracts a specific claim from a JWT token by its type.
		/// </summary>
		/// <param name="token">The JWT token to analyze.</param>
		/// <param name="claimType">The type of claim (e.g., ClaimTypes.Name).</param>
		/// <param name="validateLifetime">Indicates whether to validate the token's lifetime.</param>
		/// <returns>The claim, or null if not found.</returns>
		/// <exception cref="ArgumentException">If the token or claim type is null or empty.</exception>
		/// <exception cref="SecurityTokenException">If the token is invalid.</exception>
		public Claim? GetClaimFromToken(string token, string claimType, bool validateLifetime = true)
		{
			if (string.IsNullOrWhiteSpace(token))
				throw new ArgumentException("Token cannot be null or empty.", nameof(token));
			if (string.IsNullOrWhiteSpace(claimType))
				throw new ArgumentException("Claim type cannot be null or empty.", nameof(claimType));

			var claims = GetClaimsFromToken(token, validateLifetime);
			return claims.FirstOrDefault(c => c.Type == claimType);
		}
	}
}