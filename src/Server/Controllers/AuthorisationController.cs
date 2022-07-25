using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Server.Authentication;
using Server.Contracts.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

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

        // Token encoding details
        public String JWTKey { get; internal set; }
        public String JWTIssuer { get; internal set; }
        public String JWTAudience { get; internal set; }
        public Int16 AccessTokenExpiry { get => 60; }
        public Int16 RefreshTokenExpiry { get => 3600; }
        public SymmetricSecurityKey JWTSecurityKey { get; internal set; }
        public SigningCredentials JWTSigningCredentials { get; internal set; }


        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        public AuthorisationController(
            ILogger<SessionController> logger,
            IUserAuthenticator userAuthenticator,
            String JWTKey,
            String JWTIssuer,
            String JWTAudience)
        {
            // Assign the logger family
            _logger = logger;

            // Assign the user authentication method to create JWT Tokens from
            _userAuthenticator = userAuthenticator;

            // Set up the signing credentials for JWT Tokens
            this.JWTKey = JWTKey;
            this.JWTIssuer = JWTIssuer;
            this.JWTAudience = JWTAudience;
            JWTSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(this.JWTKey));
            JWTSigningCredentials = new SigningCredentials(JWTSecurityKey, SecurityAlgorithms.HmacSha256Signature);
        }

        // https://connect2id.com/products/server/docs/api/par
        /// <summary>
        /// Submit the request parameters directly to the server before sending the end-user to the authorisation endpoint for login and consent.
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [Route("par")]
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
        [Route("login")]
        public ActionResult Authorisation(OAuthTokenRequest request)
        {
            // Check the client id and secret being asked for;
            SecurityUser securityUser = _userAuthenticator.AuthenticateOAuth(request);
            if (securityUser != null)
            {
                // Generate a new JWT Header to wrap the token
                JwtHeader header = new JwtHeader(JWTSigningCredentials);

                // Combine the claims list to a standard claim array for the JWT payload
                List<Claim> mergedClaims = new List<Claim>()
                {
                /*    new Claim(ClaimTypes.NameIdentifier, securityUser.Id),
                    new Claim(ClaimTypes.Name, securityUser.Username)*/
                };
                mergedClaims.AddRange(securityUser.Claims);

                // Create the content of the JWT Token with the appropriate expiry date
                // and claims to identify who the user is and what they are able to do
                JwtPayload payload = new JwtPayload(
                    this.JWTIssuer,
                    this.JWTAudience,
                    mergedClaims,
                    DateTime.UtcNow,
                    DateTime.UtcNow.AddSeconds(this.AccessTokenExpiry));

                // Generate the final tokem from the header and it's payload
                JwtSecurityToken secToken = new JwtSecurityToken(header, payload);

                // Token to String so you can use it in the client
                String tokenString = (new JwtSecurityTokenHandler()).WriteToken(secToken);

                return new OkObjectResult(
                    new OAuthTokenSuccess()
                    {
                        AccessToken = tokenString,
                        ExpiresIn = this.AccessTokenExpiry,
                        RefreshToken = tokenString,
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
        [Route("token")]
        public ActionResult Token()
        {
            return new OkResult();
        }

        // https://connect2id.com/products/server/docs/api/token-introspection
        /// <summary>
        /// Validate an access token and retrieve its underlying authorisation (for resource servers).
        /// </summary>
        /// <returns></returns> 
        [HttpPost]
        [Route("token/intospect")]
        public ActionResult TokenIntrospection()
        {
            return new OkResult();
        }

        // https://connect2id.com/products/server/docs/api/token-revocation
        /// <summary>
        /// Revoke an obtained access or refresh token.
        /// </summary>
        /// <returns></returns> 
        [HttpPost]
        [Route("token/revoke")]
        public ActionResult TokenRevocation()
        {
            return new OkResult();
        }
    }
}