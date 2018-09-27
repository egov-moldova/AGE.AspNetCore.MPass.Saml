using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using static Microsoft.AspNetCore.Hosting.Internal.HostingApplication;

namespace Test.Pages
{
    [Authorize]
    public class LoginModel: PageModel
    {
        public async Task OnGetAsync()
        {

        }
    }
}