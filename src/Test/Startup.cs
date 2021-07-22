using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using AGE.AspNetCore.MPass.Saml;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Test
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }
        private IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.Configure<MPassSamlOptions>(MPassSamlDefaults.AuthenticationScheme, Configuration.GetSection("MPassSamlOptions"));

            services.AddAuthentication(sharedOptions =>
            {
                sharedOptions.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                sharedOptions.DefaultChallengeScheme = MPassSamlDefaults.AuthenticationScheme;
            })
            .AddCookie(options =>
            {
                options.Cookie.Name = "auth";
                options.Cookie.SameSite = SameSiteMode.None;
            })
            .AddMPassSaml();

            services.AddControllers();

            services.AddHealthChecks()
                .AddMPassSamlHealthCheck(MPassSamlDefaults.AuthenticationScheme);
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app)
        {
            app.UseDeveloperExceptionPage();
            
            app.UseStaticFiles();
            app.UseHealthChecks("/health");
            app.UseAuthentication();

            app.UseRouting();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });

            app.Run(async context =>
            {
                if (context.Request.Path.Equals("/signedout"))
                {
                    await WriteHtmlAsync(context.Response, async res =>
                    {
                        await res.WriteAsync($"<h1>You have been signed out.</h1>");
                        await res.WriteAsync("<a class=\"btn btn-link\" href=\"/\">Sign In</a>");
                    });
                    return;
                }

                if (context.Request.Path.Equals("/signout"))
                {
                    if (context.User.Identities.Any(identity => identity.IsAuthenticated))
                        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    await WriteHtmlAsync(context.Response, async res =>
                    {
                        await context.Response.WriteAsync($"<h1>Signed out {HtmlEncode(context.User.Identity.Name)}</h1>");
                        await context.Response.WriteAsync("<a class=\"btn btn-link\" href=\"/\">Sign In</a>");
                    });
                    return;
                }

                if (context.Request.Path.Equals("/signout-remote"))
                {
                    if (context.User.Identity.IsAuthenticated)
                    {
                        // Redirects
                        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                        await context.SignOutAsync(MPassSamlDefaults.AuthenticationScheme, new AuthenticationProperties
                        {
                            RedirectUri = "/signedout"
                        });
                        return;
                    }

                    await WriteHtmlAsync(context.Response, async res =>
                    {
                        await context.Response.WriteAsync($"<h1>Signed out {HtmlEncode(context.User.Identity.Name)}</h1>");
                        await context.Response.WriteAsync("<a class=\"btn btn-link\" href=\"/\">Sign In</a>");
                    });
                    return;
                }

                // DefaultAuthenticateScheme causes User to be set
                var user = context.User;

                // Not authenticated
                if (user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
                {
                    // This is what [Authorize] calls
                    await context.ChallengeAsync();

                    return;
                }

                await WriteHtmlAsync(context.Response, async response =>
                {
                    await response.WriteAsync($"<h1>Hello Authenticated User {HtmlEncode(user.Identity.Name)}</h1>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout\">Sign Out</a>");
                    await response.WriteAsync("<a class=\"btn btn-default\" href=\"/signout-remote\">Sign Out Remote</a>");

                    await response.WriteAsync("<h2>Claims:</h2>");
                    await WriteTableHeader(response, new string[] { "Claim Type", "Value" }, context.User.Claims.Select(c => new string[] { c.Type, c.Value }));
                });
            });
        }
        private static async Task WriteHtmlAsync(HttpResponse response, Func<HttpResponse, Task> writeContent)
        {
            var bootstrap = "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\" integrity=\"sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u\" crossorigin=\"anonymous\">";

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
