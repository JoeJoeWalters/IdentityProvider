using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Server.Authentication;
using Server.Contracts.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Security.Cryptography;
using Server.Contracts;
using Server.Helpers;
using Newtonsoft.Json;

namespace Server.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [ApiController]
    public class AuthorisationController : ControllerBase
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
        public AuthorisationController(
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

        // https://connect2id.com/products/server/docs/api/authorization
        /// <summary>
        /// The client sends the end-user's browser here to request the user's authentication and consent. This endpoint is used in the code and implicit OAuth 2.0 flows which require end-user interaction.
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [Route(URIs.authorization_endpoint)]
        public ActionResult Authorisation([FromQuery]OAuthTokenRequest request)
        {
            // Check the client id and secret being asked for;
            SecurityUser securityUser = _userAuthenticator.AuthenticateOAuth(request);
            if (securityUser != null)
            {
                DateTime now = DateTime.UtcNow; // Fixed point in quantum

                // Generate a new JWT Header to wrap the token
                JwtHeader header = new JwtHeader(_signingCredentials);
                header.Add("kid", _serverSettings.PublicKey.ComputeSha1Hash());

                // Combine the claims list to a standard claim array for the JWT payload
                List<Claim> claims = new List<Claim>()
                {
                    new Claim("scope", "test")
                };
                claims.AddRange(securityUser.Claims);

                // Create the content of the JWT Token with the appropriate expiry date
                JwtPayload secPayload = new JwtPayload(
                    this._serverSettings.Issuer,
                    this._serverSettings.Audience,
                    claims,
                    now,
                    now.AddSeconds(this._accessTokenExpiry));

                // Create the content of the refresh JWT Token with the appropriate expiry date
                JwtPayload refreshPayload = new JwtPayload(
                    this._serverSettings.Issuer,
                    this._serverSettings.Audience,
                    claims,
                    now,
                    now.AddSeconds(this._refreshTokenExpiry));

                // Generate the final tokem from the header and it's payload
                JwtSecurityToken secToken = new JwtSecurityToken(header, secPayload);
                JwtSecurityToken refreshToken = new JwtSecurityToken(header, refreshPayload);

                // Token to String so you can use it in the client
                String tokenString = (new JwtSecurityTokenHandler()).WriteToken(secToken);

                string refreshTokenString = (new JwtSecurityTokenHandler()).WriteToken(refreshToken);

                return new OkObjectResult(
                    new OAuthTokenSuccess()
                    {
                        AccessToken = tokenString,
                        ExpiresIn = this._accessTokenExpiry,
                        RefreshToken = refreshTokenString,
                        Scope = "test",
                        TokenType = "bearer"
                    });
            }
            else
            {
                return new BadRequestObjectResult(
                    new OAuthTokenFailure()
                    {
                        Reason = OAuthTokenFailure.ReasonType.unauthorized_client,
                        ReasonDescription = "Reason for the failure here",
                        ReasonUri = "url of the failure code"
                    });
            }
        }

        // https://connect2id.com/products/server/docs/api/token
        /// <summary>
        /// Post an OAuth 2.0 grant (code, refresh token, resource owner password credentials, client credentials) to obtain an ID and / or access token.
        /// </summary>
        /// <returns></returns> 
        [HttpPost]
        [Route(URIs.token_endpoint)]
        public ActionResult Token()
        {
            return new OkResult();
        }

        // https://datatracker.ietf.org/doc/html/rfc7662#section-2.1
        /// <summary>
        /// Validate an access token and retrieve its underlying authorisation (for resource servers).
        /// </summary>
        /// <returns></returns> 
        [HttpPost]
        [Route(URIs.introspection_endpoint)]
        public ActionResult TokenIntrospection([FromQuery]TokenIntrospectionRequest request)
        {
            RSA rsa = RSA.Create();
            rsa.ImportFromPem(_serverSettings.PublicKey.ToCharArray());

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            TokenValidationParameters validationParameters = new TokenValidationParameters
            {
                ValidIssuer = _serverSettings.Issuer,
                ValidAudiences = new[] { _serverSettings.Audience },
                IssuerSigningKeys = new List<SecurityKey> { new RsaSecurityKey(rsa) }
            };

            try
            {
                ClaimsPrincipal principal = handler.ValidateToken(request.token, validationParameters, out SecurityToken jsonToken);
                JwtSecurityToken token = jsonToken as JwtSecurityToken;
                return new OkObjectResult(new TokenIntrospectionResponse() { active = true, scope = token.Claims.Where(claim => claim.Type.ToLower() == "scope").FirstOrDefault().Value, exp = token.Payload.Exp });
            }
            catch (Exception ex)
            {
            }

            return new UnauthorizedObjectResult(new TokenIntrospectionResponse() { active = false });
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