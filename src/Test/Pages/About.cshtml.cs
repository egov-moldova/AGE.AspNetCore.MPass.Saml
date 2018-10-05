using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Test.Pages
{
    [Authorize]
    public class AboutModel : PageModel
    {
        public string UserName { get; set; }

        public void OnGet()
        {
            UserName = HttpContext.User.Identity.Name;
        }
    }
}
