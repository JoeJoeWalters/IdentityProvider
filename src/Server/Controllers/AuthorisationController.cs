﻿using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
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
        private readonly IPasscodeService _passcodeService;
        private readonly ServerSettings _serverSettings;

        public AuthorisationController(ITokenStorage tokenStorage, IAuthenticator authenticator, IPasscodeService passcodeService, ServerSettings serverSettings)
        {
            _tokenStorage = tokenStorage;
            _authenticator = authenticator;
            _passcodeService = passcodeService;
            _serverSettings = serverSettings;
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

                    SecurityData methodData = _authenticator.GetByUsername(model.TokenRequest.Username); // Get the credential properties based on the username so we can determine the types of authrication it can use

                    List<SelectListItem> authOptions = new List<SelectListItem>()
                    {
                        new SelectListItem("Passcode", CustomGrantTypes.Passcode),
                        new SelectListItem("OTP", CustomGrantTypes.OTP)
                    };

                    IndexModel selectMethodModel = new IndexModel() { Request = model.Request, Step = AuthoriseStep.SelectMethod, AuthOptions = authOptions, TokenRequest = model.TokenRequest };
                    return View("~/Views/Authorisation/Index.cshtml", selectMethodModel);

                case AuthoriseStep.SelectMethod:

                    SecurityData entryData = _authenticator.GetByUsername(model.TokenRequest.Username); // Get the credential properties based on the username so we can determine the types of authrication it can use
                    IndexModel methodEntryModel = new IndexModel() { Request = model.Request, Step = AuthoriseStep.MethodEntry, AuthOptions = new List<SelectListItem>(), TokenRequest = model.TokenRequest };

                    switch (model.TokenRequest.Type)
                    {
                        case CustomGrantTypes.Passcode:

                            // Ask the pin service which positions we should be asking for by asking for X digits of the Y that are available
#warning 3 is an arbitory number right now, make a service setting
                            List<int> positions = _passcodeService.RandomPositions(entryData.Passcode, 3);

                            // Map the positions to the model
                            List<string> passcodeDigitsSetup = new List<string>();
                            List<Boolean> passcodeDigitsActiveSetup = new List<bool>();
                            for (int pos = 0; pos < _serverSettings.PasscodeSize; pos++)
                            {
                                passcodeDigitsSetup.Add("");
                                passcodeDigitsActiveSetup.Add(positions.Contains(pos));
                            }

                            methodEntryModel.PasscodeDigits = passcodeDigitsSetup;
                            methodEntryModel.PasscodeDigitsActive = passcodeDigitsActiveSetup;
                            methodEntryModel.AuthOptions.Add(new SelectListItem("Passcode", CustomGrantTypes.Passcode));
                            return View("~/Views/Authorisation/Index.cshtml", methodEntryModel);

                        case CustomGrantTypes.OTP:

                            methodEntryModel.AuthOptions.Add(new SelectListItem("OTP", CustomGrantTypes.OTP));
                            return View("~/Views/Authorisation/Index.cshtml", methodEntryModel);
                    }

                    break;


                case AuthoriseStep.MethodEntry:

                    switch (model.TokenRequest.Type)
                    {
                        case CustomGrantTypes.Passcode:

                            // Convert input fields in to format accepted by the service
                            List<KeyValuePair<int, string>> passcodeDigits = new List<KeyValuePair<int, string>>();
                            for (int pos = 0; pos < model.PasscodeDigits.Count; pos++)
                            {
                                if (model.PasscodeDigitsActive[pos])
                                {
                                    passcodeDigits.Add(new KeyValuePair<int, string>(pos, model.PasscodeDigits[pos]));
                                }
                            }

                            // Create the custom request to pass to the authentication service
                            model.TokenRequest.Passcode = passcodeDigits;
                            JwtSecurityToken result = _authenticator.AuthenticateCustom(model.TokenRequest);

                            if (result != null)
                            {
                                string code = _tokenStorage.Add(result);

                                AuthoriseResponse response = new AuthoriseResponse() { code = code, state = "" };
                                String queryString = response.ToQueryString<AuthoriseResponse>();

                                string url = $"{model.TokenRequest.RedirectUri}?{queryString}";
                                return new RedirectResult(url);
                            }

                            break;

                        case CustomGrantTypes.OTP:

                            break;

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
