using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Server.Contracts.Tokens;
using Server.Helpers;
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
    public class Authenticator : IAuthenticator
    {
        /// <summary>
        /// Local cached list of users
        /// </summary>
        private AccessControl accessControl = new AccessControl() { };

        private readonly ServerSettings _serverSettings;
        private readonly SigningCredentials _signingCredentials;

        public TokenValidationParameters JWTValidationParams { get; internal set; }

        /// <summary>
        /// Default Constructor
        /// </summary>
        /// <param name="tokenValidationParameters">Validation parameters for the JWT Tokens</param>
        public Authenticator()
            => RefreshAccessList(); // Get the new access control list

        public Authenticator(
            TokenValidationParameters tokenValidationParameters,
            SigningCredentials signingCredentials,
            ServerSettings serverSettings)
        {
            this.JWTValidationParams = tokenValidationParameters; // Assign the validator for the JWT tokens
            _serverSettings = serverSettings;
            _signingCredentials = signingCredentials;
            RefreshAccessList(); // Get the new access control list
        }

        /// <summary>
        /// Custom grant type fulfillment
        /// </summary>
        /// <param name="tokenRequest"></param>
        /// <returns></returns>
        public JwtSecurityToken AuthenticateCustom(CustomTokenRequest tokenRequest)
            => Task.Run(() => AuthenticateCustomAsync(tokenRequest)).Result;

        /// <summary>
        /// Custom grant type fulfillment
        /// </summary>
        /// <param name="tokenRequest"></param>
        /// <returns></returns>
        public async Task<JwtSecurityToken> AuthenticateCustomAsync(CustomTokenRequest tokenRequest)
        {
            SecurityData data = null;
            DateTime now = DateTime.UtcNow; // Fixed point in time

            switch (tokenRequest.Type)
            {
                case CustomGrantTypes.Pin:



                    break;
            }

            return await GenerateTokenFromSecurityData(data, now);
        }

        /// <summary>
        /// OAuth grant type mode fulfillment
        /// </summary>
        /// <param name="tokenRequest"></param>
        /// <returns></returns>
        public JwtSecurityToken AuthenticateOAuth(OAuthTokenRequest tokenRequest)
            => Task.Run(() => AuthenticateOAuthAsync(tokenRequest)).Result;

        /// <summary>
        /// OAuth grant type mode fulfillment
        /// </summary>
        /// <param name="tokenRequest"></param>
        /// <returns></returns>
        public async Task<JwtSecurityToken> AuthenticateOAuthAsync(OAuthTokenRequest tokenRequest)
        {
            SecurityData data = null;
            DateTime now = DateTime.UtcNow; // Fixed point in time

            try
            {
                switch (tokenRequest.Type)
                {
                    case GrantTypes.ClientCredentials:

                        data = accessControl
                            .Clients
                            .Where(client =>
                            {
                                return
                                    client.Id == tokenRequest.Client_Id &&
                                    client.Secret == tokenRequest.Client_Secret;
                            }).Select(client => new SecurityData() { ClientId = client.Id }).FirstOrDefault();

                        break;

                    case GrantTypes.Password:

                        data = accessControl
                            .Users
                            .Where(user =>
                            {
                                return
                                    user.Username == tokenRequest.Username &&
                                    user.Password == tokenRequest.Password &&
                                    user.ClientId == tokenRequest.Client_Id;
                            }).FirstOrDefault();

                        break;

                    case GrantTypes.AuthorisationCode:

                        data = accessControl
                            .Users
                            .Where(user =>
                            {
                                return
                                    user.Key == tokenRequest.Code &&
                                    user.ClientId == tokenRequest.Client_Id;
                            }).FirstOrDefault();

                        break;

                    default:

                        break;
                }
            }
            catch (Exception ex)
            {
            };

            return await GenerateTokenFromSecurityData(data, now);

        }

        private async Task<JwtSecurityToken> GenerateTokenFromSecurityData(SecurityData data, DateTime now)
        {
            long unixTime = (new DateTimeOffset(now)).ToUnixTimeSeconds();

            if (data != null)
            {
                // Generate a new JWT Header to wrap the token
                JwtHeader header = new JwtHeader(_signingCredentials);
                header.Add("kid", _serverSettings.PublicKey.ComputeSha1Hash());

                // Combine the claims list to a standard claim array for the JWT payload
                List<Claim> claims = new List<Claim>()
                {
                    new Claim("scope", "test")
                };
                claims.AddRange(data.Claims);
                claims.Add(new Claim("sub", data.Id)); // Add the user id as the subject (sub claim) 
                claims.Add(new Claim("ait", unixTime.ToString())); // Creation Time claim

                // Create the content of the JWT Token with the appropriate expiry date
                JwtPayload secPayload = new JwtPayload(
                    _serverSettings.Issuer,
                    _serverSettings.Audiences.Where(aud => aud.Primary).FirstOrDefault().Name,
                    claims,
                    now.AddSeconds(-1), // For the bots
                    now.AddSeconds(_serverSettings.AccessTokenExpiry));

                // Generate the final tokem from the header and it's payload
                JwtSecurityToken token = new JwtSecurityToken(header, secPayload);

                return await Task.FromResult<JwtSecurityToken>(token);
            }
            else
            {
            }

#warning "TODO"
            throw new Exception();
        }

        /// <summary>
        /// Take a token (usually from the auth token in the header) and validate the
        /// user
        /// </summary>
        /// <param name="securityToken">The security token, usually from the header</param>
        /// <returns>The user that was found and validated, a null will be returned if no user was validated</returns>
        public JwtSecurityToken AuthenticateToken(String securityToken)
            => Task.Run(() => AuthenticateTokenAsync(securityToken)).Result;

        public async Task<JwtSecurityToken> AuthenticateTokenAsync(String securityToken)
        {
            // Not authorised by default
            SecurityData result = null;

            // The time the token started to validate so it is consistent
            DateTime tokenReceivedTime = DateTime.UtcNow;

            try
            {
                // Basic authentication requested
                AuthenticationHeaderValue authHeader;
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

                            // Did we get a principal?
                            if (principal != null && validatedToken != null)
                            {
                                return await Task.FromResult<JwtSecurityToken>((JwtSecurityToken)validatedToken);
                            }
                        }
                        else
                        {
                            throw new Exception("Not a JWT token");
                        }

                        break;

                    default:

                        break;
                }
            }
            catch (Exception ex)
            {
                throw ex;
            }

#warning "TODO"
            throw new Exception();
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
                    string raw = reader.ReadToEnd();
                    return RefreshAccessList(
                        JsonConvert.DeserializeObject<AccessControl>(raw)
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
