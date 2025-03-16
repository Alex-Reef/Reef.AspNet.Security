using System.Security.Claims;

namespace Reef.AspNet.Security
{
	public interface IJwtService
	{
		string GenerateRefreshToken();
		string GenerateToken(List<Claim> claims);
		ClaimsPrincipal GetPrincipalFromExpiredToken(string token);
		List<Claim> GetClaimsFromToken(string token, bool validateLifetime = true);
		Claim? GetClaimFromToken(string token, string claimType, bool validateLifetime = true);
	}
}
