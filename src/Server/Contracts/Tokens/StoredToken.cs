﻿using System.IdentityModel.Tokens.Jwt;

namespace IdentityServer.Server.Contracts.Tokens
{
    /// <summary>
    /// Storage medium for JWT tokens that may be recalled by the authorisation code and the PKCE challenge method
    /// </summary>
    public class StoredToken
    {
        /// <summary>
        /// The stored token
        /// </summary>
        public JwtSecurityToken Token { get; set; }
        
        /// <summary>
        /// THe code challenge (The given hash of the verifier generated by the client)
        /// </summary>
        public string? CodeChallenge { get; set; }

        /// <summary>
        /// The method of hashing that was used so it can be repeated when the code is 
        /// requested to verify the hash e.g. SHA256
        /// </summary>
        public string? CodeChallengeMethod { get; set; }
    }
}
