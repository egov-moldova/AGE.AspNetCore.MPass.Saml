using System;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using AGE.AspNetCore.MPass.Saml.Events;

namespace AGE.AspNetCore.MPass.Saml
{
    public class MPassSamlOptions : RemoteAuthenticationOptions
    {
        public MPassSamlOptions()
        {
            CallbackPath = MPassSamlDefaults.CallbackPath;
            LogoutRequestPath = MPassSamlDefaults.LogoutRequestPath;
            LogoutResponsePath = MPassSamlDefaults.LogoutResponsePath;
            Events = new MPassSamlEvents();
        }

        /// <summary>
        /// Check that the options are valid.  Should throw an exception if things are not ok.
        /// </summary>
        public override void Validate()
        {
            base.Validate();

            if (!CallbackPath.HasValue)
            {
                throw new ArgumentException("Options.CallbackPath must be provided.", nameof(CallbackPath));
            }

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
        /// Sign out scheme.
        /// </summary>
        public string SignOutScheme { get; set; }

        /// <summary>
        /// Gets or sets the type used to secure data handled by the handler.
        /// </summary>
        public ISecureDataFormat<AuthenticationProperties> StateDataFormat { get; set; }

        /// <summary>
        /// Requests received on this path will cause the handler to invoke SignOut using the SignInScheme.
        /// </summary>
        public PathString LogoutRequestPath { get; set; }

        /// <summary>
        /// The request path within the application's base path where the user agent will be returned after sign out from the identity provider.
        /// </summary>
        public PathString LogoutResponsePath { get; set; }

        /// <summary>
        /// Indicates if invalid SAML Response to the CallbackPath shall fail, so that they are not passed through other authentication handlers.
        /// Enabling this and setting the CallbackPath to a dedicated endpoint may provide better error handling.
        /// This is disabled by default.
        /// </summary>
        public bool FailOnInvalidResponse { get; set; }

        /// <summary>
        /// The uri where the user agent will be redirected to when an invalid SAML Response is provided to CallbackPath.
        /// The redirect will happen only when <see cref="FailOnInvalidResponse"/> is disabled.
        /// </summary>
        /// <remarks>This URI can be out of the application's domain. By default it points to the root.</remarks>
        public string InvalidResponseRedirectUri { get; set; } = "/";

        /// <summary>
        /// The uri where the user agent will be redirected to after application is signed out from the identity provider.
        /// The redirect will happen after the <see cref="LogoutResponsePath"/> is invoked.
        /// </summary>
        /// <remarks>This URI can be out of the application's domain. By default it points to the root.</remarks>
        public string SignedOutRedirectUri { get; set; } = "/";

        /// <summary>
        /// Gets or sets the <see cref="MPassSamlEvents"/> to notify when processing SAML messages.
        /// </summary>
        public new MPassSamlEvents Events
        {
            get => (MPassSamlEvents)base.Events;
            set => base.Events = value;
        }

    }
}
