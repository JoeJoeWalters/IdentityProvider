using Microsoft.IdentityModel.Tokens;
using Server.Contracts.Tokens;
using System.IdentityModel.Tokens.Jwt;

namespace Server.Services
{
    /// <summary>
    /// Store and retrieve security tokens
    /// </summary>
    public class TokenStorage : ITokenStorage
    {
        // Storage for the security tokens
        private readonly Dictionary<string, StoredToken> _tokens;

        /// <summary>
        /// Construct the token storage
        /// </summary>
        public TokenStorage()
        {
            _tokens = new Dictionary<string, StoredToken>();
        }

        /// <summary>
        /// Add a security token to the token storage in exchange for an identifier
        /// </summary>
        /// <param name="token">The security token to store</param>
        /// <returns>Identifier for the token</returns>
        public string Add(JwtSecurityToken token, string? codeChallenge, string? codeChallengeMethod)
        {
            string id = Guid.NewGuid().ToString();
            StoredToken storage = new StoredToken()
            {
                Token = token,
                CodeChallenge = codeChallenge,
                CodeChallengeMethod = codeChallengeMethod
            };
            _tokens.Add(id, storage);
            return id;
        }

        /// <summary>
        /// Exchange an identifier for the security token
        /// </summary>
        /// <param name="id">The token identifier</param>
        /// <returns>The security token</returns>
        public JwtSecurityToken Retrieve(string id, string? codeVerifier)
        {
            JwtSecurityToken token = _tokens[id].Token;
            _tokens.Remove(id);
            return token;
        }
    }
}
