using Microsoft.AspNetCore.Mvc;

namespace Server.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [ApiController]
    public class FederationController : ControllerBase
    {
        private readonly ILogger<SessionController> _logger;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        public FederationController(ILogger<SessionController> logger)
        {
            _logger = logger;
        }

        // https://connect2id.com/products/server/docs/api/federation-client-registration
        /// <summary>
        /// Create an explicit client registration with a server participating in a OpenID Connect federation.
        /// </summary>
        /// <returns></returns>
        [HttpPost]
        [Obsolete("Not Implemented Yet")]
        [Route("federation/clients")]
        public ActionResult FederationClients()
        {
            return new OkResult();
        }
    }
}