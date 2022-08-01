using Client.Pages.AuthorizeCallback;
using Microsoft.AspNetCore.Mvc;

namespace Client.Controllers
{
    public class AuthorizeCallbackController : Controller
    {
        [HttpGet]
        [Route("AuthorizeCallback")]
        public IActionResult AuthorizeCallbackGet()
        {
            return View("~/Pages/AuthorizeCallback/Index.cshtml", new IndexModel());
        }

        [HttpPost]
        [Route("AuthorizeCallback")]
        public IActionResult AuthorizeCallbackPost()
        {
            return View("~/Pages/AuthorizeCallback/Index.cshtml", new IndexModel());
        }
    }
}
