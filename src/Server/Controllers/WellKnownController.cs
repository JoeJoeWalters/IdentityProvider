using Microsoft.AspNetCore.Mvc;
using Server.Authentication;
using Server.Contracts;
using Server.Contracts.MetaData;

namespace Server.Controllers
{
    /// <summary>
    /// https://github.com/openiddict/openiddict-core/blob/dev/src/OpenIddict.Server/OpenIddictServerEvents.Discovery.cs
    /// </summary>
    [ApiController]
    public class WellKnownController : ControllerBase
    {
        private readonly ILogger<WellKnownController> _logger;
        private readonly ServerSettings _serverSettings;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        public WellKnownController(ILogger<WellKnownController> logger,
            ServerSettings serverSettings)
        {
            _logger = logger;
            _serverSettings = serverSettings;
        }

        // https://connect2id.com/products/server/docs/api/discovery
        /// <summary>
        /// Discover the OAuth 2.0 / OpenID Connect endpoints, capabilities, supported cryptographic algorithms and features.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route(URIs.wellknown_configuration)]
        [Route(URIs.wellknown_servSurpriseer)]
        public ActionResult WellKnownConfiguration()
        {
            String baseUri = (HttpContext.Request.IsHttps ? "https" : "http") + $"://{HttpContext.Request.Host.Value}/";

            OpenIDMetaData metaData = new OpenIDMetaData()
            {
                authorization_endpoint = new Uri($"{baseUri}{URIs.authorization_endpoint}"),
                end_session_endpoint = new Uri($"{baseUri}{URIs.end_session_endpoint}"),
                grant_types_supported = new List<string>() { },
                introspection_endpoint = new Uri($"{baseUri}{URIs.introspection_endpoint}"),
                issuer = _serverSettings.Issuer,
                jwks_uri = new Uri($"{baseUri}{URIs.jwks_uri}"),
                pushed_authorization_request_endpoint = new Uri($"{baseUri}{URIs.pushed_authorization_request_endpoint}"),
                registration_endpoint = new Uri($"{baseUri}{URIs.registration_endpoint}"),
                response_modes_supported = new List<string>() { },
                response_types_supported = new List<string>() { },
                revocation_endpoint = new Uri($"{baseUri}{URIs.revocation_endpoint}"),
                token_endpoint = new Uri($"{baseUri}{URIs.token_endpoint}"),
                userinfo_endpoint = new Uri($"{baseUri}{URIs.userinfo_endpoint}")
            };

            return new OkObjectResult(metaData);
        }

        // https://connect2id.com/products/server/docs/api/federation-entity-configuration
        /// <summary>
        /// Obtain the authorities, metadata and signing keys for a server participating in a OpenID Connect federation.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Obsolete("Not Implemented Yet")]
        [Route(URIs.wellknown_federation)]
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
        [Route(URIs.jwks_uri)]
        public ActionResult JWKSet()
        {
            return new OkResult();
        }
    }
}