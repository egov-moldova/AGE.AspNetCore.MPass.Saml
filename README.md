# MPass SAML Authentication

This package is intended for Service Provider integration built on ASP.NET Core 2.0+ with MPass using SAML v2.0 protocol and format for authentication.

### Getting Started

Please go through the following instructions to integrate your project with MPass.

### Prerequisites

Before being able to integrate with MPass, a Service Provider, including its certificate, must be registered accordingly in MPass.
MPass accepts certificates issued by [STISC](https://stisc.gov.md/).

### Installing

Install the following package from [NuGet](https://www.nuget.org/packages/AGE.AspNetCore.MPass.Saml/1.0.1)

```
Install-Package AGE.AspNetCore.MPass.Saml
```

Then follow the instructions from Configuration and Usage sections below.

### Configuration

Add the following configuration section to your **appsettings.json**:
```
{
	...
	"MPassSamlOptions": {
		"SamlRequestIssuer": "https://sampleservice.md",
		"ServiceCertificatePath": "Files\\Certificates\\sampleservice.md.pfx",
		"ServiceCertificatePassword": "yourpfxpassword",
		"IdentityProviderCertificatePath": "Files\\Certificates\\testmpass.gov.md.cer",
		"SamlMessageTimeout": "00:10:00",
		"SamlLoginDestination": "https://testmpass.gov.md/login/saml",
		"SamlLogoutDestination": "https://testmpass.gov.md/logout/saml",
		"ServiceRootUrl": "https://localhost:44379"
	}
	...
}
```
where **ServiceRootUrl** is the base path of your published service.

Please note that your Service must be published using **https** protocol.

### Usage

Add the following code snippet to your **Startup.ConfigureServices** method:
```
services.AddAuthentication(sharedOptions =>
{
    sharedOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    sharedOptions.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    sharedOptions.DefaultChallengeScheme = MPassSamlDefaults.AuthenticationScheme;
})
.AddCookie()
.AddMPassSaml(options => Configuration.GetSection("MPassSamlOptions").Bind(options));
```

In your **Startup.Configure** add the Authentication Middleware before **_app.UseMvc()_**:

```
app.UseAuthentication();
```
To initiate authentication is required to add "**[Authorize]**" atribute to your Controller.

```

    [Authorize]
    public class AboutModel : PageModel
    {
        public string UserName { get; set; }

        public void OnGet()
        {
            UserName = HttpContext.User.Identity.Name;
        }
    }
```

To initiate Logout is required to add following code to your Logout method.

```

await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
await HttpContext.SignOutAsync(MPassSamlDefaults.AuthenticationScheme, new AuthenticationProperties() { RedirectUri = redirectUri });
```
Note: "**redirectUri**" -> is query parameter that specify where to redirect user after Logout.
```

<li><a asp-page="/logout" asp-route-redirectUri="@Context.Request.Path.Value">LogOut - @User.Identity.Name</a></li>          
```