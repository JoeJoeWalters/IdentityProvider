using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Server.Authentication;
using Server.Contracts;
using Server.Contracts.Tokens;
using Server.Helpers;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace Server.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [ApiController]
    public class TokenController : ControllerBase
    {
        private readonly ILogger<SessionController> _logger;
        private readonly IUserAuthenticator _userAuthenticator;
        private readonly ServerSettings _serverSettings;

        private Int16 _accessTokenExpiry { get => 60; }
        private Int16 _refreshTokenExpiry { get => 3600; }

        // https://vmsdurano.com/-net-core-3-1-signing-jwt-with-rsa/
        private SigningCredentials _signingCredentials { get; set; }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="userAuthenticator"></param>
        /// <param name="serverSettings"></param>
        public TokenController(
            ILogger<SessionController> logger,
            IUserAuthenticator userAuthenticator,
            ServerSettings serverSettings)
        {
            // Assign the logger family
            _logger = logger;

            // Assign the user authentication method to create tokens from
            _userAuthenticator = userAuthenticator;

            // Set up the signing credentials for tokens
            _serverSettings = serverSettings;

            //RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(2048);
            RSA rsa = RSA.Create();
            rsa.ImportFromPem(_serverSettings.PrivateKey.ToCharArray());

            _signingCredentials = new SigningCredentials(new RsaSecurityKey(rsa), SecurityAlgorithms.RsaSha256Signature, SecurityAlgorithms.Sha256Digest)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };
        }

        // https://connect2id.com/products/server/docs/api/par
        /// <summary>
        /// Submit the request parameters directly to the server before sending the end-user to the authorisation endpoint for login and consent.
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [Route(URIs.pushed_authorization_request_endpoint)]
        public ActionResult PushedAuthorisationRequests()
        {
            return new OkResult();
        }

        // https://connect2id.com/products/server/docs/api/token
        /// <summary>
        /// Post an OAuth 2.0 grant (code, refresh token, resource owner password credentials, client credentials) to obtain an ID and / or access token.
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [Route(URIs.token_endpoint)]
        public ActionResult Token([FromQuery] TokenRequest request)
        {
            DateTime now = DateTime.UtcNow; // Fixed point in time
            long unixTime = (new DateTimeOffset(now)).ToUnixTimeSeconds();

            var handler = new JwtSecurityTokenHandler();

            // No authentication needed if a refresh token is being given
            if (request.Type == GrantTypes.RefreshToken)
            {
                // https://stackoverflow.com/questions/57481524/what-is-encoded-in-refresh-token
                // https://stackoverflow.com/questions/39890282/oauth2-0-what-should-be-the-content-format-of-refresh-token-before-encryption
                // Go look up the corresponding given token and refresh it, add to the expiry and hand back again

                // Generate the new token from the refresh token as that holds the same data that was previously agreed
                JwtSecurityToken token = (new JwtSecurityToken(request.Refresh_Token)).GenerateFromRefreshToken(_accessTokenExpiry, now, _signingCredentials, _serverSettings);

                // Generate the new refresh token from the generated token
                JwtSecurityToken refreshToken = token.GenerateRefreshToken(_refreshTokenExpiry, now, _signingCredentials, _serverSettings);

                try
                {

                    return new OkObjectResult(
                        new TokenSuccess()
                        {
                            AccessToken = handler.WriteToken(token),
                            ExpiresIn = _accessTokenExpiry,
                            RefreshToken = handler.WriteToken(refreshToken),
                            Scope = "",
                            TokenType = "bearer"
                        });
                }
                catch (Exception ex)
                {
                    return new BadRequestObjectResult(
                        new TokenFailure()
                        {
                            Reason = TokenFailure.ReasonType.invalid_request,
                            ReasonDescription = "Could not process given refresh token",
                            ReasonUri = ""
                        });
                }
            }
            else
            {
                // Check the client id and secret being asked for;
                SecurityUser securityUser = _userAuthenticator.AuthenticateOAuth(request);
                if (securityUser != null)
                {
                    // Generate a new JWT Header to wrap the token
                    JwtHeader header = new JwtHeader(_signingCredentials);
                    header.Add("kid", _serverSettings.PublicKey.ComputeSha1Hash());

                    // Combine the claims list to a standard claim array for the JWT payload
                    List<Claim> claims = new List<Claim>()
                    {
                        new Claim("scope", "test")
                    };
                    claims.AddRange(securityUser.Claims);
                    claims.Add(new Claim("sub", securityUser.Id)); // Add the user id as the subject (sub claim) 
                    claims.Add(new Claim("ait", unixTime.ToString())); // Creation Time claim

                    // Create the content of the JWT Token with the appropriate expiry date
                    JwtPayload secPayload = new JwtPayload(
                        _serverSettings.Issuer,
                        request.Audience.IsNullOrEmpty() ? _serverSettings.Audiences.Where(aud => aud.Primary).FirstOrDefault().Name : request.Audience,
                        claims,
                        now.AddSeconds(-1), // For the bots
                        now.AddSeconds(_accessTokenExpiry));

                    // Generate the final tokem from the header and it's payload
                    JwtSecurityToken token = new JwtSecurityToken(header, secPayload);
                    JwtSecurityToken refreshToken = token.GenerateRefreshToken(_refreshTokenExpiry, now, _signingCredentials, _serverSettings);

                    return new OkObjectResult(
                        new TokenSuccess()
                        {
                            AccessToken = handler.WriteToken(token),
                            ExpiresIn = _accessTokenExpiry,
                            RefreshToken = handler.WriteToken(refreshToken),
                            Scope = "",
                            TokenType = "bearer"
                        });
                }
                else
                {
                    return new BadRequestObjectResult(
                        new TokenFailure()
                        {
                            Reason = TokenFailure.ReasonType.unauthorized_client,
                            ReasonDescription = "Reason for the failure here",
                            ReasonUri = ""
                        });
                }
            }
        }

        // https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
        /// <summary>
        /// Validate an access token and retrieve its underlying authorisation (for resource servers).
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [HttpPost]
        [Route(URIs.introspection_endpoint)]
        public ActionResult TokenIntrospection([FromQuery] TokenIntrospectionRequest request)
        {
            RSA rsa = RSA.Create();
            rsa.ImportFromPem(_serverSettings.PublicKey.ToCharArray());

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidIssuer = _serverSettings.Issuer,
                ValidAudiences = _serverSettings.Audiences.Select(aud => aud.Name).ToArray(),
                IssuerSigningKeys = new List<SecurityKey> { new RsaSecurityKey(rsa) }
            };

            try
            {
                ClaimsPrincipal principal = handler.ValidateToken(request.token, validationParameters, out SecurityToken jsonToken);
                JwtSecurityToken token = jsonToken as JwtSecurityToken;

                string type = token.Header["typ"].ToString().ToLower();

                if ((type.ToLower().IsNullOrEmpty() ? "jwt" : type) == request.token_type_hint.ToLower())
                    return new OkObjectResult(
                        JsonConvert.SerializeObject(
                            new TokenIntrospectionResponse() { active = true, scope = token.Claims.Where(claim => claim.Type.ToLower() == "scope").FirstOrDefault().Value, exp = token.Payload.Exp },
                            Formatting.Indented,
                            new JsonSerializerSettings
                            {
                                NullValueHandling = NullValueHandling.Ignore
                            }));
            }
            catch (SecurityTokenInvalidAudienceException audEx)
            {

            }
            catch (SecurityTokenInvalidAlgorithmException algEx)
            {

            }
            catch (SecurityTokenInvalidIssuerException issEx)
            {

            }
            catch (SecurityTokenInvalidSignatureException sigEx)
            {

            }
            catch (SecurityTokenInvalidLifetimeException expEx)
            {

            }
            catch (Exception ex)
            {
            }

            return new UnauthorizedObjectResult(
                JsonConvert.SerializeObject(
                    new TokenIntrospectionResponse() { active = false },
                    Formatting.Indented,
                    new JsonSerializerSettings
                    {
                        NullValueHandling = NullValueHandling.Ignore
                    }));
        }

        // https://connect2id.com/products/server/docs/api/token-revocation
        /// <summary>
        /// Revoke an obtained access or refresh token.
        /// </summary>
        /// <returns></returns> 
        [HttpPost]
        [Route(URIs.revocation_endpoint)]
        public ActionResult TokenRevocation()
        {
            return new OkResult();
        }

        // https://connect2id.com/products/server/docs/api/logout
        /// <summary>
        /// Let a client application (OpenID relying party) notify the Identity Provider (IdP) that an end-user has logged out of the application
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [Route(URIs.revocation_endpoint)]
        public ActionResult LogOut()
        {
            return new OkResult();
        }
    }
}