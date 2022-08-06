using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Server.Services
{
    /// <summary>
    /// Store and retrieve security tokens
    /// </summary>
    public class TokenStorage : ITokenStorage
    {
        // Storage for the security tokens
        private readonly Dictionary<string, JwtSecurityToken> _tokens;

        /// <summary>
        /// Construct the token storage
        /// </summary>
        public TokenStorage()
        {
            _tokens = new Dictionary<string, JwtSecurityToken>();
        }

        /// <summary>
        /// Add a security token to the token storage in exchange for an identifier
        /// </summary>
        /// <param name="token">The security token to store</param>
        /// <returns>Identifier for the token</returns>
        public string Add(JwtSecurityToken token)
        {
            string id = Guid.NewGuid().ToString();
            _tokens.Add(id, token);
            return id;
        }

        /// <summary>
        /// Exchange an identifier for the security token
        /// </summary>
        /// <param name="id">The token identifier</param>
        /// <returns>The security token</returns>
        public JwtSecurityToken Retrieve(string id)
        {
            JwtSecurityToken token = _tokens[id];
            _tokens.Remove(id);
            return token;
        }
    }
}
