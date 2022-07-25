using Microsoft.AspNetCore.Mvc;

namespace Server.Controllers
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
        [Route("userinfo")]
        public ActionResult UserInfo()
        {
            return new OkResult();
        }

        // https://connect2id.com/products/server/docs/api/logout
        /// <summary>
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