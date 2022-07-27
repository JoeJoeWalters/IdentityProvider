using System.IdentityModel.Tokens.Jwt;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Claims;

namespace Server.Helpers
{
    /// <summary>
    /// Helpers for generating and manipulating tokens
    /// </summary>
    public static class TokenHelper
    {
        /// <summary>
        /// Generate the refresh token from the security token
        /// </summary>
        /// <param name="token"></param>
        /// <param name="expiry"></param>
        /// <param name="issuedTime"></param>
        /// <returns></returns>
        public static JwtSecurityToken GenerateRefreshToken(this JwtSecurityToken token, Int32 expiry, DateTime issuedTime)
        {
            // Clone the token
            JwtHeader clonedHeader = new JwtHeader(token.Header.SigningCredentials);
            JwtPayload clonedPayload = new JwtPayload(
                    token.Issuer,
                    token.Audiences.First(),
                    new List<Claim>(token.Claims),
                    issuedTime,
                    issuedTime.AddSeconds(expiry));
            return new JwtSecurityToken(clonedHeader, clonedPayload);
        }

        /// <summary>
        /// Generate a new security token from the refresh token
        /// </summary>
        /// <param name="token"></param>
        /// <param name="expiry"></param>
        /// <param name="issuedTime"></param>
        /// <returns></returns>
        public static JwtSecurityToken GenerateFromRefreshToken(this JwtSecurityToken token, Int32 expiry, DateTime issuedTime)
        {
            // Clone the token
            JwtHeader clonedHeader = new JwtHeader(token.Header.SigningCredentials);
            JwtPayload clonedPayload = new JwtPayload(
                    token.Issuer,
                    token.Audiences.First(),
                    new List<Claim>(token.Claims),
                    issuedTime,
                    issuedTime.AddSeconds(expiry));
            return new JwtSecurityToken(clonedHeader, clonedPayload);
        }
    }
}
