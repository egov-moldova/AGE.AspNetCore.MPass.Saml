namespace MPassSamlNuget
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
    }
}
