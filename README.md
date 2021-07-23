# MPass SAML Authentication

This package is intended for Service Provider integration built on ASP.NET Core 2.0+ with MPass using SAML v2.0 protocol and format for authentication.

### Getting Started

Please go through the following instructions to integrate your project with MPass.

### Prerequisites

Before being able to integrate with MPass, a Service Provider, including its certificate, must be registered accordingly in MPass.
MPass accepts certificates issued by [STISC](https://stisc.gov.md/).

### Installing

Install the following package from [NuGet](https://www.nuget.org/packages/AGE.AspNetCore.MPass.Saml/1.0.9)

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
		"ServiceRootUrl": "https://localhost:5000"
	}
	...
}
```
where **ServiceRootUrl** is the base path of your published service.

Please note that your Service must be published using **https** protocol.

### Usage

Add the following code snippet to your **Startup.ConfigureServices** method:
```
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
```

In your **Startup.Configure** add the Authentication Middleware.

```
app.UseAuthentication();
```