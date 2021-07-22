using Microsoft.AspNetCore.Http;

namespace AGE.AspNetCore.MPass.Saml
{
    /// <summary>
    /// Default values related to MPass authentication handler
    /// </summary>
    public static class MPassSamlDefaults
    {
        /// <summary>
        /// The default value used for MPass.AuthenticationScheme.
        /// </summary>
        public const string AuthenticationScheme = "MPass";

        /// <summary>
        /// The default value for the display name.
        /// </summary>
        public static readonly string DisplayName = "MPass";

        /// <summary>
        /// The default value for Saml Request.
        /// </summary>
        public static readonly string SAMLRequest = "SAMLRequest";

        /// <summary>
        /// The default value for Saml Response.
        /// </summary>
        public static readonly string SAMLResponse = "SAMLResponse";

        /// <summary>
        /// The default value for Session Index.
        /// </summary>
        public static readonly string SessionIndex = "SessionIndex";

        /// <summary>
        /// The default value for Relay State.
        /// </summary>
        public static readonly string RelayState = "RelayState";

        /// <summary>
        /// The default value used by MPassSamlHandler for the MPassSamlOptions.CallbackPath.
        /// </summary>
        public static readonly PathString CallbackPath = "/mpass-login";

        /// <summary>
        /// The default value used by MPassSamlHandler for the MPassSamlOptions.LogoutRequestPath.
        /// </summary>
        public static readonly PathString LogoutRequestPath = "/mpass-slo";

        /// <summary>
        /// The default value used by MPassSamlHandler for the MPassSamlOptions.LogoutResponsePath.
        /// </summary>
        public static readonly PathString LogoutResponsePath = "/mpass-logout";
    }
}
