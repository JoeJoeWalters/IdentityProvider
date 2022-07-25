using Microsoft.AspNetCore.Mvc;

namespace Server.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [ApiController]
    public class AuthorisationController : ControllerBase
    {
        private readonly ILogger<SessionController> _logger;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        public AuthorisationController(ILogger<SessionController> logger)
        {
            _logger = logger;
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
        public ActionResult Authorisation()
        {
            return new OkResult();
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