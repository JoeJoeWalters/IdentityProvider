using Microsoft.IdentityModel.Tokens;
using Server.Authentication;
using Server.Exceptions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace Server.Helpers
{
    /// <summary>
    /// Helpers for generating and manipulating tokens
    /// </summary>
    public static class TokenHelper
    {
        private static List<string> dontCloneClaims = new List<string>() { "aud", "iat" };

        /// <summary>
        /// Generate the refresh token from the security token
        /// </summary>
        /// <param name="token"></param>
        /// <param name="expiry"></param>
        /// <param name="issuedTime"></param>
        /// <param name="signingCredentials"></param>
        /// <returns></returns>
        public static JwtSecurityToken GenerateRefreshToken(this JwtSecurityToken token, Int32 expiry, DateTime issuedTime, SigningCredentials signingCredentials, ServerSettings serverSettings)
        {
            var isToken = (token.Header.Typ ?? String.Empty) == "JWT";
            if (isToken)
            {
                // Clone the token
                JwtHeader clonedHeader = new JwtHeader(signingCredentials);
                clonedHeader["typ"] = "Refresh"; // Change the token type from JWT to Refresh to avoid token re-use
                clonedHeader.Add("kid", serverSettings.PublicKey.ComputeSha1Hash());

                long unixTime = (new DateTimeOffset(issuedTime)).ToUnixTimeSeconds();
                List<Claim> mergedClaims = new List<Claim>(token.Claims.Where(claim => !dontCloneClaims.Contains(claim.Type)));
                mergedClaims.Add(new Claim("ait", unixTime.ToString())); // Creation Time claim

                JwtPayload clonedPayload = new JwtPayload(
                        token.Issuer,
                        token.Audiences.First(),
                        mergedClaims,
                        issuedTime.AddSeconds(-1), // 1 second off to avoid bots
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
        public static JwtSecurityToken GenerateFromRefreshToken(this JwtSecurityToken token, Int32 expiry, DateTime issuedTime, SigningCredentials signingCredentials, ServerSettings serverSettings)
        {
            var isRefresh = (token.Header.Typ ?? String.Empty) == "Refresh";
            if (isRefresh)
            {
                // Clone the token
                JwtHeader clonedHeader = new JwtHeader(signingCredentials);
                clonedHeader.Add("kid", serverSettings.PublicKey.ComputeSha1Hash());

                long unixTime = (new DateTimeOffset(issuedTime)).ToUnixTimeSeconds();
                List<Claim> mergedClaims = new List<Claim>(token.Claims.Where(claim => !dontCloneClaims.Contains(claim.Type)));
                mergedClaims.Add(new Claim("ait", unixTime.ToString())); // Creation Time claim

                JwtPayload clonedPayload = new JwtPayload(
                        token.Issuer,
                        token.Audiences.First(),
                        mergedClaims,
                        issuedTime.AddSeconds(-1), // 1 second off to avoid bots
                        issuedTime.AddSeconds(expiry));
                return new JwtSecurityToken(clonedHeader, clonedPayload);
            }

            throw new UnprocessableTokenException();
        }
    }
}
