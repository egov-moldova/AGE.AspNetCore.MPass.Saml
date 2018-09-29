using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Test.Pages
{
    [Authorize(Roles ="test")]
    public class ContactModel : PageModel
    {
        public string Message { get; set; }

        public void OnGet()
        {
            //try
            //{
            //    if (HttpContext.User?.FindFirst("Role")?.Value == "administrator")
            //        HttpContext.ForbidAsync(new AuthenticationProperties() { RedirectUri = "/Error" });
            //}
            //catch (Exception e ) { }
            Message = "Your contact page.";
        }
    }
}
