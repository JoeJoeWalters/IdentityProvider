using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Server.Authentication;
using Server.Contracts;
using Server.Contracts.Tokens;
using Server.Helpers;
using Server.Services;
using Server.Views.Authorisation;
using System.IdentityModel.Tokens.Jwt;

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
                CustomTokenRequest request = new CustomTokenRequest()
                {
                    Client_Id = "7ac39504-53f1-47f5-96b9-3c2682962b8b",                    
                    Type = CustomGrantTypes.Pin,
                    Username = "admin_a",
                    Pin = new List<KeyValuePair<int, string>>()
                    {
                        new KeyValuePair<int, string>( 0, "A" ),
                        new KeyValuePair<int, string>(  2, "2" ),
                        new KeyValuePair<int, string>(  5, "5" )
                    },
                    RedirectUri = $"https://localhost:7053/authorizeCallback",
                };
                JwtSecurityToken result = _authenticator.AuthenticateCustom(request);

                if (result != null)
                {
                    string code = _tokenStorage.Add(result);

                    AuthoriseResponse response = new AuthoriseResponse() { code = code, state = "" };
                    String queryString = response.ToQueryString<AuthoriseResponse>();

                    string url = $"{request.RedirectUri}?{queryString}";
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
