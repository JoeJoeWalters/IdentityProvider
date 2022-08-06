using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Server.Authentication;
using Server.Contracts;
using Server.Contracts.Tokens;
using Server.Helpers;
using Server.Views.Authorisation;

namespace Server.Controllers
{
    /// <summary>
    /// 
    /// </summary>
    public class AuthorisationController : Controller
    {
        private readonly ITokenStorage _tokenStorage;
        private readonly IAuthenticator _authenticator;

        public AuthorisationController(ITokenStorage tokenStorage, IAuthenticator authenticator)
        {
            _tokenStorage = tokenStorage;
            _authenticator = authenticator;
        }

        // GET: AuthorisationController
        [HttpGet]
        [Route(URIs.authorization_endpoint)]
        public ActionResult Index(AuthoriseRequest request)
        {
            IndexModel model = new IndexModel() { Request = request };
            return View(model);
        }

        [HttpPost]
        [Route(URIs.authorization_endpoint)]
        public ActionResult Post()
        {
            try
            {
                CustomTokenRequest request = new CustomTokenRequest() { };
                SecurityToken result = _authenticator.AuthenticateCustom(request);

                if (result != null)
                {
                    string code = _tokenStorage.Add(result);

                    AuthoriseResponse response = new AuthoriseResponse() { code = code, state = "" };
                    String queryString = response.ToQueryString<AuthoriseResponse>();

                    string url = $"https://localhost:7053/authorizeCallback?{queryString}";
                    return new RedirectResult(url);
                }
                else
                    return View();
            }
            catch
            {
                return View();
            }
        }

        // GET: AuthorisationController/Edit/5
        public ActionResult Edit(int id)
        {
            return View();
        }

        // POST: AuthorisationController/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }

        // GET: AuthorisationController/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: AuthorisationController/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                return RedirectToAction(nameof(Index));
            }
            catch
            {
                return View();
            }
        }
    }
}
