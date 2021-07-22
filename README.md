# MPass SAML Authentication

This package is intended for Service Provider integration built on ASP.NET Core 2.0+ with MPass using SAML v2.0 protocol and format for authentication.

### Getting Started

Please go through the following instructions to integrate your project with MPass.

### Prerequisites

Before being able to integrate with MPass, a Service Provider, including its certificate, must be registered accordingly in MPass.
MPass accepts certificates issued by [STISC](https://stisc.gov.md/).

### Installing

Install the following package from [NuGet](https://www.nuget.org/packages/AGE.AspNetCore.MPass.Saml/1.0.8)

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
    sharedOptions.DefaultChallengeScheme = MPassSamlDefaults.AuthenticationScheme;
})
.AddCookie()
.AddMPassSaml(options => Configuration.GetSection("MPassSamlOptions").Bind(options));
```

In your **Startup.Configure** add the Authentication Middleware.

```
app.UseAuthentication();
```
Authentication is started automatically if you are not already authenticated with code ->

```

	// DefaultAuthenticateScheme causes User to be set
    var user = context.User;

    // Not authenticated
    if (user == null || !user.Identities.Any(identity => identity.IsAuthenticated))
    {
        // This is what [Authorize] calls
        await context.ChallengeAsync();

        return;
    }
```

LogOut is initiated then **Sign Out** and **Sign Out Remote** buttons are pressed.  
For local logout is used next part of code.
```

	if (context.Request.Path.Equals("/signout"))
    {
        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        await WriteHtmlAsync(context.Response, async res =>
        {
            await context.Response.WriteAsync($"<h1>Signed out {HtmlEncode(context.User.Identity.Name)}</h1>");
            await context.Response.WriteAsync("<a class=\"btn btn-link\" href=\"/\">Sign In</a>");
        });
        return;
    }
```

For remote logout is used next part of code.
```

	if (context.Request.Path.Equals("/signout-remote"))
    {
        if (context.User.Identity.IsAuthenticated)
        {
            // Redirects
            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            await context.SignOutAsync(MPassSamlDefaults.AuthenticationScheme,
                new AuthenticationProperties()
                {
                    RedirectUri = "/signedout"
                });
            return;
        }
        else
        {
            await WriteHtmlAsync(context.Response, async res =>
            {
                await context.Response.WriteAsync($"<h1>Signed out {HtmlEncode(context.User.Identity.Name)}</h1>");
                await context.Response.WriteAsync("<a class=\"btn btn-link\" href=\"/\">Sign In</a>");
            });
            return;
        }

    }
```
