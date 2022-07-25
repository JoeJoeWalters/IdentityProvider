using Microsoft.AspNetCore.Mvc;

namespace Server.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    [ApiController]
    public class ClientsController : ControllerBase
    {
        private readonly ILogger<SessionController> _logger;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logger"></param>
        public ClientsController(ILogger<SessionController> logger)
        {
            _logger = logger;
        }

        // https://connect2id.com/products/server/docs/api/client-registration
        /// <summary>
        /// Get a list of client registrations.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("clients")]
        public ActionResult GetClients()
        {
            return new OkResult();
        }

        // https://connect2id.com/products/server/docs/api/client-registration
        /// <summary>
        /// Get a client registration.
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("clients/{id}")]
        public ActionResult GetClient(string id)
        {
            return new OkResult();
        }

        // https://connect2id.com/products/server/docs/api/client-registration
        /// <summary>
        /// Update a client registration.
        /// </summary>
        /// <returns></returns>
        [HttpPut]
        [Route("clients/{id}")]
        public ActionResult AddClient(string id)
        {
            return new OkResult();
        }

        // https://connect2id.com/products/server/docs/api/client-registration
        /// <summary>
        /// Delete a client registration.
        /// </summary>
        /// <returns></returns>
        [HttpDelete]
        [Route("clients/{id}")]
        public ActionResult DeleteClient(string id)
        {
            return new OkResult();
        }
    }
}