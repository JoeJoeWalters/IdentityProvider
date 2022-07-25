using Server.Contracts.Tokens;
using System;
using System.IO;
using System.Threading.Tasks;

namespace Server.Authentication
{
    /// <summary>
    /// Interface to specify how user authenticator's should behave
    /// User authenticators handle the authentication of users when a request
    /// is made to the api
    /// </summary>
    public interface IUserAuthenticator
    {
        /// <summary>
        /// Take an OAuth grant request (usually from the auth token in the header) and validate the
        /// user (or resource depending on how you look at it)
        /// </summary>
        /// <param name="token">The security token, usually from the header</param>
        /// <returns>The user that was found and validated, a null will be returned if no user was validated</returns>
        SecurityUser AuthenticateToken(String token);
        Task<SecurityUser> AuthenticateTokenAsync(String token);

        /// <summary>
        /// Authenticate the client id and secret against the "users" (clients in their own right essentially)
        /// </summary>
        /// <param name="tokenRequest">OAuth Request Payload</param>
        /// <returns>The user that was found and validated, a null will be returned if no user was validated</returns>
        SecurityUser AuthenticateOAuth(OAuthTokenRequest tokenRequest);
        Task<SecurityUser> AuthenticateOAuthAsync(OAuthTokenRequest tokenRequest);
        
        /// <summary>
        /// Refresh the list of cached users that are validated against
        /// </summary>
        /// <returns>If the refresh was successful</returns>
        Boolean RefreshAccessList();
        Boolean RefreshAccessList(Stream stream);
        Boolean RefreshAccessList(AccessControl accessControl);
    }
}