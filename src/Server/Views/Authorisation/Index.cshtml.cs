using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Server.Contracts.Tokens;

namespace Server.Views.Authorisation
{
    /// <summary>
    /// What step of the authorisation screen should be showing
    /// </summary>
    public enum AuthoriseStep: int
    {
        UserEntry = 0,
        SelectMethod = 1,
        MethodEntry = 2
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
        public CustomTokenRequest TokenRequest { get; set; } = new CustomTokenRequest() { };
    }
}
