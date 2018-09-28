using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;

namespace MPassSamlNuget
{
    public class MPassSamlOptions : RemoteAuthenticationOptions
    {
        public MPassSamlOptions()
        {
            CallbackPath = "/mpass-login";
            LogoutResponsePath = "/mpass-logout";
            LogoutRequestPath = "/mpass-slo";
            SignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme; 
        }

        public string SamlRequestIssuer { get; set; }
        public string ServiceCertificate { get; set; }
        public string ServiceCertificatePassword { get; set; }
        public string IdentityProviderCertificate { get; set; }
        public string SamlMessageTimeout { get; set; }
        public string SamlLoginDestination { get; set; }
        public string SamlLogoutDestination { get; set; }
        public string DataProtectionKeysPath { get; set; }
        public string ServiceRootUrl { get; set; }

        public string SignOutScheme { get; set; }
        /// <summary>
        /// Gets or sets the type used to secure data handled by the handler.
        /// </summary>
        public ISecureDataFormat<string> StateDataFormat { get; set; }

        /// <summary>
        /// The request path within the application's base path where the user agent will be returned after sign out from the identity provider.
        /// </summary>
        public PathString LogoutResponsePath { get; set; }

        /// <summary>
        /// Requests received on this path will cause the handler to invoke SignOut using the SignInScheme.
        /// </summary>
        public PathString LogoutRequestPath { get; set; }
       
    }
}
