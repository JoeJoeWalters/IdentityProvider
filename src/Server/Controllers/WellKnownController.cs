using Microsoft.AspNetCore.Mvc;

namespace Server.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [ApiController]
    public class WellKnownController : ControllerBase
    {
        private readonly ILogger<SessionController> _logger;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        public WellKnownController(ILogger<SessionController> logger)
        {
            _logger = logger;
        }

        // https://connect2id.com/products/server/docs/api/discovery
        /// <summary>
        /// Discover the OAuth 2.0 / OpenID Connect endpoints, capabilities, supported cryptographic algorithms and features.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route(".well-known/openid-configuration")]
        [Route(".well-known/oauth-authorization-servSurpriseer")]
        public ActionResult WellKnownConfiguration()
        {
            return new OkResult();
        }

        // https://connect2id.com/products/server/docs/api/federation-entity-configuration
        /// <summary>
        /// Obtain the authorities, metadata and signing keys for a server participating in a OpenID Connect federation.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Obsolete("Not Implemented Yet")]
        [Route(".well-known/openid-federation")]
        public ActionResult FederationConfiguration()
        {
            return new OkResult();
        }

        // https://connect2id.com/products/server/docs/api/jwk-set
        /// <summary>
        /// Retrieve the public server JSON Web Key (JWK) to verify the signature of an issued token or to encrypt request objects to it.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("jwks.json")]
        public ActionResult JWKSet()
        {
            return new OkResult();
        }
    }
}