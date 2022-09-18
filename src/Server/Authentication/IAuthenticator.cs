using Microsoft.IdentityModel.Tokens;
using IdentityProvider.Server.Contracts.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.IO;
using System.Threading.Tasks;

namespace IdentityProvider.Server.Authentication;

/// <summary>
/// Interface to specify how user authenticator's should behave
/// User authenticators handle the authentication of users when a request
/// is made to the api
/// </summary>
public interface IAuthenticator
{
    /// <summary>
    /// Take an OAuth grant request (usually from the auth token in the header) and validate the
    /// user (or resource depending on how you look at it)
    /// </summary>
    /// <param name="token">The security token, usually from the header</param>
    /// <returns>The user that was found and validated, a null will be returned if no user was validated</returns>
    JwtSecurityToken AuthenticateToken(String token);
    Task<JwtSecurityToken> AuthenticateTokenAsync(String token);

    /// <summary>
    /// Authenticate the client id and secret against the "users" (clients in their own right essentially)
    /// </summary>
    /// <param name="tokenRequest">OAuth Request Payload</param>
    /// <returns>The user that was found and validated, a null will be returned if no user was validated</returns>
    JwtSecurityToken AuthenticateOAuth(OAuthTokenRequest tokenRequest);
    Task<JwtSecurityToken> AuthenticateOAuthAsync(OAuthTokenRequest tokenRequest);

    /// <summary>
    /// Authenticate via custom methods (pin / face etc. from the authorize endpoint)
    /// </summary>
    /// <param name="tokenRequest">OAuth Request Payload</param>
    /// <returns>The user that was found and validated, a null will be returned if no user was validated</returns>
    JwtSecurityToken AuthenticateCustom(CustomTokenRequest tokenRequest);
    Task<JwtSecurityToken> AuthenticateCustomAsync(CustomTokenRequest tokenRequest);

    /// <summary>
    /// Get the security data of a credential based on the username (for choosing what authentication options to display etc.)
    /// </summary>
    /// <returns></returns>
    SecurityData GetByUsername(string username);
}