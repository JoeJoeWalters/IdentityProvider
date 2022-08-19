using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using Server.Authentication;
using Server.Contracts;
using Server.Contracts.Services;
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
        private readonly IPinService _pinService;
        private readonly IOTPService _otpService;
        private readonly ServerSettings _serverSettings;
        private readonly ILogger<AuthorisationController> _logger;

        public AuthorisationController(ILogger<AuthorisationController> logger, ITokenStorage tokenStorage, IAuthenticator authenticator, IPinService pinService, IOTPService otpService, ServerSettings serverSettings)
        {
            _logger = logger;
            _tokenStorage = tokenStorage;
            _authenticator = authenticator;
            _pinService = pinService;
            _serverSettings = serverSettings;
            _otpService = otpService;
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
        public async Task<ActionResult> Post(IndexModel model)
        {
            ModelState.Clear(); // To stop the model value sticking we clear the state so they are not re-populated and overwrite our changes

            // Which stage are we at?
            switch (model.Step)
            {
                case AuthoriseStep.UserEntry:

                    SecurityData methodData = _authenticator.GetByUsername(model.TokenRequest.Username); // Get the credential properties based on the username so we can determine the types of authrication it can use

                    List<SelectListItem> authOptions = new List<SelectListItem>()
                    {
                        new SelectListItem("Pin", CustomGrantTypes.Pin),
                        new SelectListItem("OTP", CustomGrantTypes.OTP)
                    };

                    IndexModel selectMethodModel = new IndexModel() { Request = model.Request, Step = AuthoriseStep.SelectMethod, AuthOptions = authOptions, TokenRequest = model.TokenRequest };
                    return View("~/Views/Authorisation/Index.cshtml", selectMethodModel);

                case AuthoriseStep.SelectMethod:

                    SecurityData entryData = _authenticator.GetByUsername(model.TokenRequest.Username); // Get the credential properties based on the username so we can determine the types of authrication it can use
                    IndexModel methodEntryModel = new IndexModel() { Request = model.Request, Step = AuthoriseStep.MethodEntry, AuthOptions = new List<SelectListItem>(), TokenRequest = model.TokenRequest };

                    switch (model.TokenRequest.Type)
                    {
                        case CustomGrantTypes.Pin:

                            // Ask the pin service which positions we should be asking for by asking for X digits of the Y that are available
#warning 3 is an arbitory number right now, make a service setting
                            List<int> positions = _pinService.RandomPositions(entryData.Pin, 3);

                            // Map the positions to the model
                            List<string> pinDigitsSetup = new List<string>();
                            List<Boolean> pinDigitsActiveSetup = new List<bool>();
                            for (int pos = 0; pos < _serverSettings.PinSize; pos++)
                            {
                                pinDigitsSetup.Add("");
                                pinDigitsActiveSetup.Add(positions.Contains(pos));
                            }

                            methodEntryModel.PinDigits = pinDigitsSetup;
                            methodEntryModel.PinDigitsActive = pinDigitsActiveSetup;
                            methodEntryModel.AuthOptions.Add(new SelectListItem("Pin", CustomGrantTypes.Pin));
                            return View("~/Views/Authorisation/Index.cshtml", methodEntryModel);

                        case CustomGrantTypes.OTP:

                            methodEntryModel.AuthOptions.Add(new SelectListItem("OTP", CustomGrantTypes.OTP));

                            methodEntryModel.OTPDeliveryOptions = new List<SelectListItem>();
                            methodEntryModel.OTPDeliveryOptions.Add(new SelectListItem("SMS (+440*******89)", "SMS:+4407123456789"));
                            methodEntryModel.OTPDeliveryOptions.Add(new SelectListItem("Email (j**@****.com)", "Email:joe@email.com"));
                            methodEntryModel.Step = AuthoriseStep.SelectDeliveryMedium;

                            return View("~/Views/Authorisation/Index.cshtml", methodEntryModel);
                    }

                    break;


                case AuthoriseStep.SelectDeliveryMedium:

                    IndexModel mediumEntryModel = new IndexModel() { Request = model.Request, Step = AuthoriseStep.MethodEntry, AuthOptions = new List<SelectListItem>(), TokenRequest = model.TokenRequest };

                    switch (model.TokenRequest.Type)
                    {
                        case CustomGrantTypes.Pin:

                            break;

                        case CustomGrantTypes.OTP:

                            String[] splitOtpOption = model.OTPDeliveryOption.Split(':');
                            SendOTPDeliveryMethod deliveryMethod = SendOTPDeliveryMethod.SMS;
                            switch (splitOtpOption[0].ToLower())
                            {
                                case "sms":
                                    deliveryMethod = SendOTPDeliveryMethod.SMS;
                                    break;
                                case "email":
                                    deliveryMethod = SendOTPDeliveryMethod.Email;
                                    break;
                                case "voice":
                                    deliveryMethod = SendOTPDeliveryMethod.Voice;
                                    break;
                            }
                            String deliveryValue = splitOtpOption[1];
                            String otpIdentifier = Guid.NewGuid().ToString();

                            SendOTPResponse response = await _otpService.SendOTP(new SendOTPRequest() { DeliveryMethod = deliveryMethod, DeliveryValue = deliveryValue, Identifier = otpIdentifier });
                            if (response.Success)
                            {
                                mediumEntryModel.AuthOptions.Add(new SelectListItem("OTP", CustomGrantTypes.OTP));

                                mediumEntryModel.OTPDeliveryOptions = new List<SelectListItem>();
                                mediumEntryModel.OTPDeliveryOptions.Add(new SelectListItem("SMS (+440*******89)", "SMS:+4407123456789"));
                                mediumEntryModel.OTPDeliveryOptions.Add(new SelectListItem("Email (j**@****.com)", "Email:joe@email.com"));
                                mediumEntryModel.TokenRequest.OTPIdentifier = otpIdentifier;

                                return View("~/Views/Authorisation/Index.cshtml", mediumEntryModel);
                            }

                            break;

                    }

                    break;

                case AuthoriseStep.MethodEntry:

                    switch (model.TokenRequest.Type)
                    {
                        case CustomGrantTypes.Pin:

                            // Convert input fields in to format accepted by the service
                            List<KeyValuePair<int, string>> pinDigits = new List<KeyValuePair<int, string>>();
                            for (int pos = 0; pos < model.PinDigits.Count; pos++)
                            {
                                if (model.PinDigitsActive[pos])
                                {
                                    pinDigits.Add(new KeyValuePair<int, string>(pos, model.PinDigits[pos]));
                                }
                            }

                            // Create the custom request to pass to the authentication service
                            model.TokenRequest.Pin = pinDigits;
                            JwtSecurityToken pinResult = _authenticator.AuthenticateCustom(model.TokenRequest);

                            if (pinResult != null)
                            {
                                string code = _tokenStorage.Add(pinResult, model.TokenRequest.CodeChallenge, model.TokenRequest.CodeChallengeMethod);

                                AuthoriseResponse response = new AuthoriseResponse() { code = code, state = "" };
                                String queryString = response.ToQueryString<AuthoriseResponse>();

                                string url = $"{model.TokenRequest.RedirectUri}?{queryString}";
                                return new RedirectResult(url);
                            }

                            break;

                        case CustomGrantTypes.OTP:

                            JwtSecurityToken otpResult = _authenticator.AuthenticateCustom(model.TokenRequest);

                            if (otpResult != null)
                            {
                                string code = _tokenStorage.Add(otpResult, model.Request.code_challenge, model.Request.code_challenge_method);

                                AuthoriseResponse response = new AuthoriseResponse() { code = code, state = "" };
                                string queryString = response.ToQueryString<AuthoriseResponse>();

                                string url = $"{model.TokenRequest.RedirectUri}?{queryString}";
                                return new RedirectResult(url);
                            }

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
