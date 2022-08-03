using Client.Pages.AuthorizeCallback;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using Server.Contracts.Tokens;

namespace Client.Controllers
{
    public class AuthorizeCallbackController : Controller
    {
        /// <summary>
        /// If retrieved via a "get"
        /// </summary>
        /// <returns></returns>
        [HttpGet]
        [Route("AuthorizeCallback")]
        public IActionResult AuthorizeCallbackGet([FromQuery]AuthoriseResponse response)
        {
            return View("~/Pages/AuthorizeCallback/Index.cshtml", new IndexModel() { ServerResponse = response, ServerResponseEncoded = JsonConvert.SerializeObject(response, Formatting.None) });
        }
    }
}
