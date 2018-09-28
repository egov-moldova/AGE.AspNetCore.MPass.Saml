using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc.RazorPages;
using MPassSamlNuget;

namespace Test.Pages
{
    public class LogoutModel : PageModel
    {
        
        public async Task OnGetAsync(string redirectUri)
        {
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(MPassSamlDefaults.AuthenticationScheme, new AuthenticationProperties() { RedirectUri = redirectUri });
        }
    }
}
