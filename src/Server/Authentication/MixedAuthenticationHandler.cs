using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace IdentityProvider.Server.Authentication
{
    public class MixedAuthenticationHandler : AuthenticationHandler<MixedAuthenticationOptions>
    {
        /// <summary>
        /// Local reference to the user authenticator
        /// </summary>
        private IAuthenticator userAuthenticator;

        /// <summary>
        /// Default constructor
        /// </summary>
        public MixedAuthenticationHandler(
            IOptionsMonitor<MixedAuthenticationOptions> options,
            ILoggerFactory loggerFactory,
            UrlEncoder encoder,
            ISystemClock clock,
            IAuthenticator userAuthenticator
            ) : base(options, loggerFactory, encoder, clock)
        {
            // Assign the user authenticator to use (could be database, json file etc.)
            this.userAuthenticator = userAuthenticator;
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
            => base.HandleChallengeAsync(properties);

        /// <summary>
        /// Authenticate the request against the cached user credentials
        /// </summary>
        /// <returns>The Success Or Failure Result Code</returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            // The security user that is found from the authentication process
            JwtSecurityToken data = null;

            // Is there an authorisation header to cehck against?
            if (!Request.Headers.ContainsKey("Authorization"))
                return AuthenticateResult.Fail("Missing Authorization Header");

            // Try and parse the authorization header
            try
            {
                StringValues header = new StringValues();
                try
                {
                    header = Request.Headers["Authorization"];
                }
                catch
                {
                    throw new Exception("No Authorisation Header Found");
                }

                // Do the authentication by passing it to the supplied user authenticator implementation
                data = userAuthenticator.AuthenticateToken(header);
            }
            catch (Exception ex)
            {
                Response.Headers.Add(new KeyValuePair<string, StringValues>(HeaderNames.WWWAuthenticate, ((ex.InnerException != null) ? ex.InnerException.Message : ex.Message)));
                return AuthenticateResult.Fail(ex.Message);
            }

            // No user was found / authenticated
            if (data == null)
                return AuthenticateResult.Fail("Couldn't Authenticate The Given Credentials");

            // Generate a new identity and inject the claims in to the identity
            var identity = new ClaimsIdentity(data.Claims, Scheme.Name) { };

            // Create the ticket required
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            // Return that the authentication was successful and return the authentication ticket
            return AuthenticateResult.Success(ticket);
        }

    }
}
