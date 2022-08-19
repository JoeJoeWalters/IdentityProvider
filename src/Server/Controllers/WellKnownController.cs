using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Server.Authentication;
using Server.Contracts;
using Server.Contracts.MetaData;
using Server.Contracts.Tokens;
using Server.Helpers;
using System.Security.Cryptography;

namespace Server.Controllers
{
    /// <summary>
    /// 
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

        /// <summary>
        /// Discover the OAuth 2.0 / OpenID Connect endpoints, capabilities, supported cryptographic algorithms and features.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route(URIs.wellknown_configuration)]
        [Route(URIs.wellknown_servSurpriseer)]
        [Produces("application/json")]
        public ActionResult WellKnownConfiguration()
        {
            String baseUri = HttpContext.GetBaseUri();

            OpenIDMetaData metaData = new OpenIDMetaData()
            {
                authorization_endpoint = new Uri($"{baseUri}{URIs.authorization_endpoint}"),
                end_session_endpoint = new Uri($"{baseUri}{URIs.end_session_endpoint}"),
                grant_types_supported = new List<string>() { GrantTypes.AuthorisationCode, GrantTypes.RefreshToken, GrantTypes.Password, GrantTypes.ClientCredentials },
                introspection_endpoint = new Uri($"{baseUri}{URIs.introspection_endpoint}"),
                issuer = _serverSettings.Issuer,
                jwks_uri = new Uri($"{baseUri}{URIs.jwks_uri}"),
                pushed_authorization_request_endpoint = new Uri($"{baseUri}{URIs.pushed_authorization_request_endpoint}"),
                registration_endpoint = new Uri($"{baseUri}{URIs.registration_endpoint}"),
                response_modes_supported = new List<string>() { "query", "fragment" },
                response_types_supported = new List<string>() { "code", "token", "id_token" },
                revocation_endpoint = new Uri($"{baseUri}{URIs.revocation_endpoint}"),
                token_endpoint = new Uri($"{baseUri}{URIs.token_endpoint}"),
                userinfo_endpoint = new Uri($"{baseUri}{URIs.userinfo_endpoint}"),
                acr_values_supported = new List<string> { ACR.LOALevel1, ACR.LOALevel2, ACR.LOALevel3, ACR.LOALevel4 }
            };

            return new OkObjectResult(JsonConvert.SerializeObject(metaData, Formatting.None));
        }

        /// <summary>
        /// Obtain the authorities, metadata and signing keys for a server participating in a OpenID Connect federation.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Obsolete("Not Implemented Yet")]
        [Route(URIs.wellknown_federation)]
        [Produces("application/json")]
        public ActionResult FederationConfiguration()
        {
            return new OkResult();
        }

        /// <summary>
        /// Retrieve the public server JSON Web Key (JWK) to verify the signature of an issued token or to encrypt request objects to it.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route(URIs.jwks_uri)]
        [Produces("application/json")]
        public ActionResult JWKSet()
        {
            // Strip the PEM down to a format where we can export it and also so we can then compute the thumbprint hash
            string strippedKey = _serverSettings.PublicKey.StripPEM();
            string sha1Hash = strippedKey.ComputeSha1Hash();

            // Get the exponent and modulus by importing to the RSA object and then exporting the parameters
            RSA imported = RSA.Create();
            imported.ImportFromPem(_serverSettings.PublicKey);
            RSAParameters properties = imported.ExportParameters(false);

            JWKS returnSet = new JWKS()
            {
                keys = new List<JWKSKey>()
                 {
                    new JWKSKey()
                    {
                        alg = "RS256",
                        e = Convert.ToBase64String(properties.Exponent),
                        kid = sha1Hash,
                        kty = "RSA",
                        n = Convert.ToBase64String(properties.Modulus),
                        use = "sig",
                        x5c = strippedKey,
                        x5t = sha1Hash
                    }
                 }
            };

            return new OkObjectResult(JsonConvert.SerializeObject(returnSet, Formatting.None));
        }
    }
}