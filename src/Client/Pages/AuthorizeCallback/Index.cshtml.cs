using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Server.Contracts.Tokens;

namespace Client.Pages.AuthorizeCallback
{
    /// <summary>
    /// 
    /// </summary>
    public class IndexModel : PageModel
    {
        /// <summary>
        /// The response returned back from the server authorisation process
        /// </summary>
        public AuthoriseResponse ServerResponse { get; set; }

        public void OnGet()
        {
        }
    }
}
