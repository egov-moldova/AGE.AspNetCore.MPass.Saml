using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using MPassSamlNuget.Events;
using System;
using System.Security.Cryptography.X509Certificates;

namespace MPassSamlNuget
{
    public class MPassSamlOptions : RemoteAuthenticationOptions
    {
        public MPassSamlOptions()
        {
            CallbackPath = "/mpass-login";
            LogoutResponsePath = "/mpass-logout";
            LogoutRequestPath = "/mpass-slo";
        }

        /// <summary>
        /// Service certificate.
        /// </summary>
        public X509Certificate2 ServiceCertificate { get; set; }

        /// <summary>
        /// Path of service certificate.
        /// </summary>
        public string ServiceCertificatePath { get; set; }

        /// <summary>
        /// Password for service certificate.
        /// </summary>
        public string ServiceCertificatePassword { get; set; }

        /// <summary>
        /// Identity provider certificate.
        /// </summary>
        public X509Certificate2 IdpCertificate { get; set; }

        /// <summary>
        /// Path of identity provider certificate.
        /// </summary>
        public string IdentityProviderCertificatePath { get; set; }

        /// <summary>
        /// Issuer of the Saml request.
        /// </summary>
        public string SamlRequestIssuer { get; set; }

        /// <summary>
        /// Timeout of a Saml message.
        /// </summary>
        public TimeSpan SamlMessageTimeout { get; set; }

        /// <summary>
        /// URL for Saml login.
        /// </summary>
        public string SamlLoginDestination { get; set; }

        /// <summary>
        /// URL for Saml logout.
        /// </summary>
        public string SamlLogoutDestination { get; set; }

        /// <summary>
        /// URL for service.
        /// </summary>
        public string ServiceRootUrl { get; set; }

        /// <summary>
        /// Sign out scheme .
        /// </summary>
        public string SignOutScheme { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the handler.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// The request path within the application's base path where the user agent will be returned after sign out from the identity provider.
        /// </summary>
        public PathString LogoutResponsePath { get; set; }

        /// <summary>
        /// Requests received on this path will cause the handler to invoke SignOut using the SignInScheme.
        /// </summary>
        public PathString LogoutRequestPath { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="OpenIdConnectEvents"/> to notify when processing OpenIdConnect messages.
        /// </summary>
        public new MPassSamlEvents Events
        {
            get => (MPassSamlEvents)base.Events;
            set => base.Events = value;
        }

    }
}
