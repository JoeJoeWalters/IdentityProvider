using Microsoft.IdentityModel.Tokens;
using IdentityServer.Server.Contracts.Tokens;
using IdentityServer.Server.Exceptions;
using System.IdentityModel.Tokens.Jwt;

namespace IdentityServer.Server.Services
{
    /// <summary>
    /// Store and retrieve security tokens
    /// </summary>
    public class TokenStorage : ITokenStorage
    {
        // Storage for the security tokens
        private readonly Dictionary<string, StoredToken> _tokens;
        private readonly ILogger<TokenStorage> _logger;
        private readonly IHashService _hashService;

        /// <summary>
        /// Construct the token storage
        /// </summary>
        public TokenStorage(ILogger<TokenStorage> logger, IHashService hashService)
        {
            _hashService = hashService;
            _tokens = new Dictionary<string, StoredToken>();
            _logger = logger;
        }

        /// <summary>
        /// Add a security token to the token storage in exchange for an identifier
        /// </summary>
        /// <param name="token">The security token to store</param>
        /// <param name="codeChallenge">The code challenge hash if one is provided as part of PKCE</param>
        /// <param name="codeChallengeMethod">The code challenge hash method if one is provided as part of PKCE</param>
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
            // Does the authentication key exist in the token storage
            if (_tokens.ContainsKey(id))
            {
                // Get the token from the storage account and see if it needs
                // to be verified with the PKCE code verifier
                StoredToken storedToken = _tokens[id];
                JwtSecurityToken token = null;

                if (storedToken.CodeChallenge == null &&
                    storedToken.CodeChallengeMethod == null &&
                    codeVerifier == null)
                {
                    token = storedToken.Token;
                }
                else
                {
                    // Try and match based on the PKCE method
                    if (storedToken.CodeChallengeMethod == "SHA256" &&
                        codeVerifier != null)
                    {
                        string hash = _hashService.CreateHash(codeVerifier);
                        if (hash == storedToken.CodeChallenge)
                            token = storedToken.Token;
                    }
                }

                // If a token match was found then remove the token from storage
                // and return the JWT token to the caller
                if (token != null)
                {
                    _tokens.Remove(id);
                    return token;
                }
            }
            
            // Drop through so not found or not matching with PKCE authentication method if required
            throw new SecurityTokenAuthenticationCodeNotFound();
        }
    }
}
