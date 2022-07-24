using Microsoft.AspNetCore.Mvc;

namespace Server.Controllers
{
    [ApiController]
    public class OAuthController : ControllerBase
    {
        private readonly ILogger<OAuthController> _logger;

        public OAuthController(ILogger<OAuthController> logger)
        {
            _logger = logger;
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/discovery
        /// Discover the OAuth 2.0 / OpenID Connect endpoints, capabilities, supported cryptographic algorithms and features.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route(".well-known/openid-configuration")]
        [Route(".well-known/oauth-authorization-server")]
        public ActionResult WellKnownConfiguration()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/federation-entity-configuration
        /// Obtain the authorities, metadata and signing keys for a server participating in a OpenID Connect federation.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route(".well-known/openid-federation")]
        public ActionResult FederationConfiguration()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/jwk-set
        /// Retrieve the public server JSON Web Key (JWK) to verify the signature of an issued token or to encrypt request objects to it.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("jwks.json")]
        public ActionResult JWKSet()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/client-registration
        /// Get a list of client registrations.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("clients")]
        public ActionResult GetClients()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/client-registration
        /// Get a client registration.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("clients/{id}")]
        public ActionResult GetClient(string id)
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/client-registration
        /// Update a client registration.
        /// </summary>
        /// <returns></returns>
        [HttpPut]
        [Route("clients/{id}")]
        public ActionResult AddClient(string id)
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/client-registration
        /// Delete a client registration.
        /// </summary>
        /// <returns></returns>
        [HttpDelete]
        [Route("clients/{id}")]
        public ActionResult DeleteClient(string id)
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/federation-client-registration
        /// Create an explicit client registration with a server participating in a OpenID Connect federation.
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Route("federation/clients")]
        public ActionResult FederationClients()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/par
        /// Submit the request parameters directly to the server before sending the end-user to the authorisation endpoint for login and consent.
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [Route("par")]
        public ActionResult PushedAuthorisationRequests()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/authorization
        /// The client sends the end-user's browser here to request the user's authentication and consent. This endpoint is used in the code and implicit OAuth 2.0 flows which require end-user interaction.
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [Route("login")]
        public ActionResult Authorisation()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/token
        /// Post an OAuth 2.0 grant (code, refresh token, resource owner password credentials, client credentials) to obtain an ID and / or access token.
        /// </summary>
        /// <returns></returns> 
        [HttpPost]
        [Route("token")]
        public ActionResult Token()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/token-introspection
        /// Validate an access token and retrieve its underlying authorisation (for resource servers).
        /// </summary>
        /// <returns></returns> 
        [HttpPost]
        [Route("token/intospect")]
        public ActionResult TokenIntrospection()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/token-revocation
        /// Revoke an obtained access or refresh token.
        /// </summary>
        /// <returns></returns> 
        [HttpPost]
        [Route("token/revoke")]
        public ActionResult TokenRevocation()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/userinfo
        /// Retrieve profile information and other attributes for a logged-in end-user.
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [Route("userinfo")]
        public ActionResult UserInfo()
        {
            return new OkResult();
        }

        /// <summary>
        /// https://connect2id.com/products/server/docs/api/logout
        /// Let a client application (OpenID relying party) notify the Identity Provider (IdP) that an end-user has logged out of the application
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [Route("logout")]
        public ActionResult LogOut()
        {
            return new OkResult();
        }


    }
}