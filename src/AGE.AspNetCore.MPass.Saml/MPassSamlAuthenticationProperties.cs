using Microsoft.AspNetCore.Authentication;

namespace AGE.AspNetCore.MPass.Saml
{
    public class MPassSamlAuthenticationProperties : AuthenticationProperties
    {
        internal const string AuthnRequestIDKey = "authnRequestID";
        internal const string LogoutRequestIDKey = "logoutRequestID";
        internal const string FailedRedirectUriKey = "failedUri";
        internal const string LanguageKey = "lang";
        private const string IsPassiveKey = "passive";

        public bool? IsPassive
        {
            get => GetBool(IsPassiveKey);
            set => SetBool(IsPassiveKey, value);
        }

        public string FailedRedirectUri
        {
            get => GetString(FailedRedirectUriKey);
            set => SetString(FailedRedirectUriKey, value);
        }

        public string Language
        {
            get => GetString(LanguageKey);
            set => SetString(LanguageKey, value);
        }
    }
}
