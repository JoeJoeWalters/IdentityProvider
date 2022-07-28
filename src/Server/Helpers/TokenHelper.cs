using Microsoft.IdentityModel.Tokens;
using Server.Exceptions;
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
        /// <param name="signingCredentials"></param>
        /// <returns></returns>
        public static JwtSecurityToken GenerateRefreshToken(this JwtSecurityToken token, Int32 expiry, DateTime issuedTime, SigningCredentials signingCredentials)
        {
            var isToken = (token.Header.Typ ?? String.Empty) == "JWT";
            if (isToken)
            {
                // Clone the token
                JwtHeader clonedHeader = new JwtHeader(signingCredentials);
                clonedHeader["typ"] = "Refresh";

                JwtPayload clonedPayload = new JwtPayload(
                        token.Issuer,
                        token.Audiences.First(),
                        new List<Claim>(token.Claims.Where(claim => claim.Type != "aud")),
                        issuedTime,
                        issuedTime.AddSeconds(expiry));
                return new JwtSecurityToken(clonedHeader, clonedPayload);
            }

            throw new UnprocessableTokenException();
        }

        /// <summary>
        /// Generate a new security token from the refresh token
        /// </summary>
        /// <param name="token"></param>
        /// <param name="expiry"></param>
        /// <param name="issuedTime"></param>
        /// <param name="signingCredentials"></param>
        /// <returns></returns>
        public static JwtSecurityToken GenerateFromRefreshToken(this JwtSecurityToken token, Int32 expiry, DateTime issuedTime, SigningCredentials signingCredentials)
        {
            var isRefresh = (token.Header.Typ ?? String.Empty) == "Refresh";
            if (isRefresh)
            {
                // Clone the token
                JwtHeader clonedHeader = new JwtHeader(signingCredentials);

                JwtPayload clonedPayload = new JwtPayload(
                        token.Issuer,
                        token.Audiences.First(),
                        new List<Claim>(token.Claims.Where(claim => claim.Type != "aud")),
                        issuedTime,
                        issuedTime.AddSeconds(expiry));
                return new JwtSecurityToken(clonedHeader, clonedPayload);
            }

            throw new UnprocessableTokenException();
        }
    }
}
