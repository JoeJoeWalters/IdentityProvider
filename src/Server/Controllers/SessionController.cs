using Microsoft.AspNetCore.Mvc;
using IdentityProvider.Server.Contracts;

namespace IdentityProvider.Server.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [ApiController]
    public class SessionController : ControllerBase
    {
        private readonly ILogger<SessionController> _logger;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        public SessionController(ILogger<SessionController> logger)
        {
            _logger = logger;
        }

        // https://connect2id.com/products/server/docs/api/userinfo
        /// <summary>
        /// Retrieve profile information and other attributes for a logged-in end-user.
        /// </summary>
        /// <returns></returns> 
        [HttpGet]
        [Route(URIs.userinfo_endpoint)]
        public ActionResult UserInfo()
        {
            return new OkResult();
        }


    }
}