using System.IdentityModel.Tokens.Jwt;

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
        /// <returns></returns>
        public static JwtSecurityToken GenerateRefreshToken(this JwtSecurityToken token)
        {
            return new JwtSecurityToken() { }; // Placeholder
        }

        /// <summary>
        /// Generate a new security token from the refresh token
        /// </summary>
        /// <param name="token"></param>
        /// <returns></returns>
        public static JwtSecurityToken GenerateFromRefreshToken(this JwtSecurityToken token)
        {
            return new JwtSecurityToken() { }; // Placeholder
        }
    }
}
