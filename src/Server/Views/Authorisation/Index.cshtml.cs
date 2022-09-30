using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc.Rendering;
using IdentityProvider.Server.Contracts.Tokens;

namespace IdentityProvider.Server.Views.Authorisation;

/// <summary>
/// What step of the authorisation screen should be showing
/// </summary>
public enum AuthoriseStep: int
{
    UserEntry = 0,
    SelectMethod = 1,
    SelectDeliveryMedium = 2,
    MethodEntry = 3
}

/// <summary>
/// 
/// </summary>
public class IndexModel
{
    /// <summary>
    /// Parameterless constructor is required for model mapping
    /// </summary>
    public IndexModel() { }

    /// <summary>
    /// The origional request
    /// </summary>
    public AuthoriseRequest Request { get; set; } = new AuthoriseRequest() { };

    /// <summary>
    /// What step of the authorisation screen should we be showing?
    /// </summary>
    public AuthoriseStep Step { get; set; } = AuthoriseStep.UserEntry;

    /// <summary>
    /// The eventual token request which we can build up over time from the screens
    /// </summary>
    public TokenRequest TokenRequest { get; set; } = new TokenRequest() { };

    /// <summary>
    /// Pin entries with strict naming due to the way 
    /// </summary>
    public List<string> PinDigits { get; set; } = new List<string>();

    /// <summary>
    /// If certain digits are active or not (for rendering)
    /// </summary>
    public List<Boolean> PinDigitsActive { get; set; } = new List<Boolean>();

    /// <summary>
    /// Drop down list of the authentication options
    /// </summary>
    public List<SelectListItem> AuthOptions { get; set; } = new List<SelectListItem>();

    /// <summary>
    /// Selected OTP Delivery option in the screen (thrown away later)
    /// </summary>
    public String OTPDeliveryOption { get; set; } = String.Empty;

    /// <summary>
    /// Drop down list of the OTP Delivery options
    /// </summary>
    public List<SelectListItem> OTPDeliveryOptions { get; set; } = new List<SelectListItem>();

    /// <summary>
    /// List of scopes that have been requested by the caller split by the space delimited method
    /// </summary>
    public List<String> Scopes { get; set; } = new List<String>();
}
