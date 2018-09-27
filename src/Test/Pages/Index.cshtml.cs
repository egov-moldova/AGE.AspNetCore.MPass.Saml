using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Test.Pages
{
    public class IndexModel : PageModel
    {
        
        public async Task OnGetAsync()
        {
            var user = HttpContext.User.Identity;
        }

        public async Task OnPostAsync()
        {
            var user = HttpContext.User;
        }
    }
}
