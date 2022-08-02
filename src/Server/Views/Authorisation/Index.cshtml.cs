using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Server.Contracts.Tokens;

namespace Server.Views.Authorisation
{
    /// <summary>
    /// 
    /// </summary>
    public class IndexModel : PageModel
    {
        /// <summary>
        /// 
        /// </summary>
        public AuthoriseRequest Request { get; set; }
    }
}
