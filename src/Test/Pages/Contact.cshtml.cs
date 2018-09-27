using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Test.Pages
{
    [Authorize(Roles ="administrator")]
    public class ContactModel : PageModel
    {
        public string Message { get; set; }

        public void OnGet()
        {
            var user = HttpContext.User;
            Message = "Your contact page.";
        }
    }
}
