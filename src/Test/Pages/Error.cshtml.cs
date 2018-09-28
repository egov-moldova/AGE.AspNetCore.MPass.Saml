using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Test.Pages
{
    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public class ErrorModel : PageModel
    {
        public string UserName { get; set; }

        public bool ShowRequestId => !string.IsNullOrEmpty(UserName);

        public void OnGet()
        {
            UserName = HttpContext.User.Identity.Name;
        }
    }
}
