using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AGE.AspNetCore.MPass.Saml;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace Test.Controllers
{
    public class HomeController : Controller
    {
        // GET: HomeController
        public async Task<ActionResult> Index(string lang = "ro")
        {
            var user = HttpContext.User;

            // Not authenticated
            if (user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
            {
                // This is what [Authorize] calls
                return Challenge(new MPassSamlAuthenticationProperties()
                {
                    RedirectUri = "/",
                    IsPassive = false,
                    FailedRedirectUri = "/signedout",
                    Language = lang
                });
            }

            await WriteHtmlAsync(HttpContext.Response, async response =>
            {
                await response.WriteAsync($"<h1>Hello Authenticated User {HtmlEncode(user.Identity.Name)}</h1>");
                await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout\">Sign Out</a>");
                await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout-remote\">Sign Out Remote</a>");

                await response.WriteAsync("<h2>Claims:</h2>");
                await WriteTableHeader(response, new [] { "Claim Type", "Value" }, HttpContext.User.Claims.Select(c => new [] { c.Type, c.Value }));
            });
            return new EmptyResult();
        }

        [HttpGet("signout")]
        public async Task<ActionResult> SignOut()
        {
            if(HttpContext.User.Identities.Any(identity => identity.IsAuthenticated))
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await WriteHtmlAsync(HttpContext.Response, async res =>
            {
                await HttpContext.Response.WriteAsync($"<h1>Signed out {HtmlEncode(HttpContext.User.Identity.Name)}</h1>");
                await HttpContext.Response.WriteAsync("<a class=\"btn btn-link\" href=\"/\">Sign In</a>");
            });
            return new EmptyResult();
        }

        [HttpGet("signedout")]
        public async Task<ActionResult> SignedOut()
        {
            if(HttpContext.User.Identities.Any(identity => identity.IsAuthenticated))
                await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await WriteHtmlAsync(HttpContext.Response, async res =>
            {
                await HttpContext.Response.WriteAsync($"<h1>Signed out {HtmlEncode(HttpContext.User.Identity.Name)}</h1>");
                await HttpContext.Response.WriteAsync("<a class=\"btn btn-link\" href=\"/\">Sign In</a>");
            });
            return new EmptyResult();
        }

        [HttpGet("signout-remote")]
        public async Task<ActionResult> SignOutRemote()
        {
            if (!HttpContext.User.Identity.IsAuthenticated) return new EmptyResult();
                // Redirects
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await HttpContext.SignOutAsync(MPassSamlDefaults.AuthenticationScheme, new AuthenticationProperties
            {
                RedirectUri = "/signedout"
            });
            await WriteHtmlAsync(HttpContext.Response, async res =>
            {
                await HttpContext.Response.WriteAsync($"<h1>Signed out {HtmlEncode(HttpContext.User.Identity.Name)}</h1>");
                await HttpContext.Response.WriteAsync("<a class=\"btn btn-link\" href=\"/\">Sign In</a>");
            });
            return new EmptyResult();
        }

        private static async Task WriteHtmlAsync(HttpResponse response, Func<HttpResponse, Task> writeContent)
        {
            var bootstrap = "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.4.1/css/bootstrap.min.css\" integrity=\"sha384-HSMxcRTRxnN+Bdg0JdbxYKrThecOKuH5zCYotlSAcp1+c8xmyTe9GYg1l9a69psu\" crossorigin=\"anonymous\">";

            response.ContentType = "text/html";
            await response.WriteAsync($"<html><head>{bootstrap}</head><body><div class=\"container\">");
            await writeContent(response);
            await response.WriteAsync("</div></body></html>");
        }

        private static async Task WriteTableHeader(HttpResponse response, IEnumerable<string> columns, IEnumerable<IEnumerable<string>> data)
        {
            await response.WriteAsync("<table class=\"table table-condensed\">");
            await response.WriteAsync("<tr>");
            foreach (var column in columns)
            {
                await response.WriteAsync($"<th>{HtmlEncode(column)}</th>");
            }
            await response.WriteAsync("</tr>");
            foreach (var row in data)
            {
                await response.WriteAsync("<tr>");
                foreach (var column in row)
                {
                    await response.WriteAsync($"<td>{HtmlEncode(column)}</td>");
                }
                await response.WriteAsync("</tr>");
            }
            await response.WriteAsync("</table>");
        }

        private static string HtmlEncode(string content) =>
            string.IsNullOrEmpty(content) ? string.Empty : HtmlEncoder.Default.Encode(content);

     
    }
}
