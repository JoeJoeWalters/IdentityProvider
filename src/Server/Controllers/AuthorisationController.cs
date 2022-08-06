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
            IndexModel model = new IndexModel() { Request = request, Step = AuthoriseStep.UserEntry, TokenRequest = new CustomTokenRequest() { RedirectUri = request.redirect_uri, Username = String.Empty, Client_Id = request.client_id } };
            return View("~/Views/Authorisation/Index.cshtml", model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Route(URIs.authorization_endpoint)]
        public ActionResult Post(IndexModel model)
        {
            ModelState.Clear(); // To stop the model value sticking we clear the state so they are not re-populated and overwrite our changes

            // Which stage are we at?
            switch (model.Step)
            {
                case AuthoriseStep.UserEntry:

                    IndexModel selectMethodModel = new IndexModel() { Request = model.Request, Step = AuthoriseStep.SelectMethod, TokenRequest = model.TokenRequest };
                    return View("~/Views/Authorisation/Index.cshtml", selectMethodModel);


                case AuthoriseStep.SelectMethod:

                    IndexModel methodEntryModel = new IndexModel() { Request = model.Request, Step = AuthoriseStep.MethodEntry, TokenRequest = model.TokenRequest };
                    return View("~/Views/Authorisation/Index.cshtml", methodEntryModel);

                case AuthoriseStep.MethodEntry:

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

                    break;
            }

            return View();
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
