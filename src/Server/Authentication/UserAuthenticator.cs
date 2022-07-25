using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Server.Contracts.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;

namespace Server.Authentication
{
    /// <summary>
    /// Standard user authenticator that reads from a Json file in a given location
    /// </summary>
    public class UserAuthenticator : IUserAuthenticator
    {
        /// <summary>
        /// Local cached list of users
        /// </summary>
        private AccessControl accessControl = new AccessControl() { };

        public TokenValidationParameters JWTValidationParams { get; internal set; }

        public SecurityUser AuthenticateOAuth(OAuthTokenRequest tokenRequest)
            => Task.Run(() => AuthenticateOAuthAsync(tokenRequest)).Result;

        public async Task<SecurityUser> AuthenticateOAuthAsync(OAuthTokenRequest tokenRequest)
        {
            SecurityUser result = null;

            // Not a JWT encoded bearer so compare to the API Key instead
            try
            {
                switch (tokenRequest.Type)
                {
                    case OAuthTokenRequest.GrantType.client_credentials:

                        result = accessControl
                            .Users
                            .Where(user =>
                            {
                                return
                                    user.ClientId == tokenRequest.ClientId &&
                                    user.ClientSecret == tokenRequest.ClientSecret &&
                                    user.Authentication.Contains(SecurityUser.AuthenticationType.oauth);
                            }).FirstOrDefault();

                        break;

                    case OAuthTokenRequest.GrantType.password:

                        result = accessControl
                            .Users
                            .Where(user =>
                            {
                                return
                                    user.Username == tokenRequest.Username &&
                                    user.Password == tokenRequest.Password &&
                                    user.Authentication.Contains(SecurityUser.AuthenticationType.oauth);
                            }).FirstOrDefault();

                        break;

                    case OAuthTokenRequest.GrantType.authorization_code:

                        result = accessControl
                            .Users
                            .Where(user =>
                            {
                                return
                                    user.Key == tokenRequest.Code &&
                                    user.Authentication.Contains(SecurityUser.AuthenticationType.oauth);
                            }).FirstOrDefault();

                        break;

                    default:

                        result = null;
                        break;
                }
            }
            catch
            {
                result = null;
            };

            return await Task.FromResult<SecurityUser>(result);
        }

        /// <summary>
        /// Take a token (usually from the auth token in the header) and validate the
        /// user
        /// </summary>
        /// <param name="securityToken">The security token, usually from the header</param>
        /// <returns>The user that was found and validated, a null will be returned if no user was validated</returns>
        public SecurityUser AuthenticateToken(String securityToken)
            => Task.Run(() => AuthenticateTokenAsync(securityToken)).Result;

        public async Task<SecurityUser> AuthenticateTokenAsync(String securityToken)
        {
            // Not authorised by default
            SecurityUser result = null;

            // The time the token started to validate so it is consistent
            DateTime tokenReceivedTime = DateTime.UtcNow;

            try
            {
                // Basic authentication requested
                AuthenticationHeaderValue authHeader = null;
                try
                {
                    authHeader = AuthenticationHeaderValue.Parse(securityToken);
                }
                catch
                {
                    throw new Exception("Authentication Header Is Malformed");
                }

                String token = authHeader.Parameter; // Get the token from the header

                switch (authHeader.Scheme.ToLower().Trim())
                {
                    case "oauth":
                    case "bearer":

                        // Expects bearer to be JWT encoded       
                        // https://jwt.io/
                        SecurityToken jwtToken = null;
                        JwtSecurityTokenHandler tokenHandler = new JwtSecurityTokenHandler();

                        try
                        {
                            jwtToken = tokenHandler.ReadToken(token);
                        }
                        catch { }

                        // No failure, must be a valid JWT encoded bearer
                        if (jwtToken != null)
                        {
                            // TODO: Get the user details from the JWT Token instead of the access control list
                            JwtSecurityToken jwtSecurityToken = (JwtSecurityToken)jwtToken;

                            // Check the expiry date of the token, if it has expired we need to tell the source
                            // system and get them to request a new token with the refresh token
                            if (!(jwtSecurityToken.ValidFrom <= tokenReceivedTime &&
                                jwtSecurityToken.ValidTo >= tokenReceivedTime))
                                throw new Exception("Lifetime validation failed. The token is expired");

                            // Validate the token and get the principal
                            SecurityToken validatedToken = null;
                            IPrincipal principal = null;
                            try
                            {
                                principal = tokenHandler.ValidateToken(
                                                            token,
                                                            JWTValidationParams,
                                                            out validatedToken);
                            }
                            catch { }

                            // Did we gain a principal?
                            if (principal != null && validatedToken != null)
                            {
                                // Transpose the principal and the token details to the user
                                return new SecurityUser()
                                {
                                    Id = jwtSecurityToken.Claims.Where(claim => claim.Type == ClaimTypes.NameIdentifier).FirstOrDefault().Value,
                                    Key = String.Empty,
                                    Username = String.Empty,
                                    Authentication = new List<SecurityUser.AuthenticationType>()
                                    {
                                        SecurityUser.AuthenticationType.oauth
                                    },
                                    Claims = jwtSecurityToken.Claims.ToList()
                                };
                            }
                        }
                        else
                        {
                            // Not a JWT encoded bearer so compare to the API Key instead
                            result = accessControl
                                .Users
                                .Where(user =>
                                {
                                    return
                                        user.Key == token &&
                                        user.Authentication.Contains(SecurityUser.AuthenticationType.apikey);
                                }).FirstOrDefault();
                        }

                        break;

                    case "basic":

                        // Get the credentials from the basic authentication paramater part
                        var credentialBytes = Convert.FromBase64String(authHeader.Parameter);

                        // Split up the credentials in the parameter and check the length being the correct size
                        var credentials = Encoding.UTF8.GetString(credentialBytes).Split(':');
                        if (credentials.Length == 2)
                        {
                            // Authorised?
                            result = accessControl
                                .Users
                                .Where(user =>
                                {
                                    return
                                        user.Password == credentials[1] &&
                                        user.Username == credentials[0] &&
                                        user.Authentication.Contains(SecurityUser.AuthenticationType.basic);
                                }).FirstOrDefault();
                        }

                        break;

                    case "apikey":

                        result = accessControl
                            .Users
                            .Where(user =>
                            {
                                return
                                    user.Key == token &&
                                    user.Authentication.Contains(SecurityUser.AuthenticationType.apikey);
                            }).FirstOrDefault();

                        break;

                    default:

                        break;
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

            return await Task.FromResult<SecurityUser>(result);
        }


        /// <summary>
        /// Default Constructor
        /// </summary>
        /// <param name="tokenValidationParameters">Validation parameters for the JWT Tokens</param>
        public UserAuthenticator()
            => RefreshAccessList(); // Get the new access control list

        public UserAuthenticator(TokenValidationParameters tokenValidationParameters)
        {
            this.JWTValidationParams = tokenValidationParameters; // Assign the validator for the JWT tokens
            RefreshAccessList(); // Get the new access control list
        }

        /// <summary>
        /// Refresh the list of cached users that are validated against
        /// </summary>
        /// <returns>If the refresh was successful</returns>
        public Boolean RefreshAccessList()
            => RefreshAccessList(new AccessControl());

        public Boolean RefreshAccessList(Stream stream)
        {
            try
            {
                using (StreamReader reader = new StreamReader(stream))
                {
                    return RefreshAccessList(
                        JsonConvert.DeserializeObject<AccessControl>(reader.ReadToEnd())
                        );
                }
            }
            catch (Exception ex)
            {
                return false;
            }
        }

        public Boolean RefreshAccessList(AccessControl accessControl)
        {
            this.accessControl = accessControl ?? new AccessControl() { };
            return true;
        }
    }
}
