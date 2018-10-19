using System;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;


namespace MPassSamlNuget
{
    public class MPassSamlHandler : RemoteAuthenticationHandler<MPassSamlOptions>, IAuthenticationSignOutHandler
    {
        private const string HeaderValueEpocDate = "Thu, 01 Jan 1970 00:00:00 GMT";

        public MPassSamlHandler(IOptionsMonitor<MPassSamlOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
         : base(options, logger, encoder, clock)
        {
        }

        public override async Task<bool> HandleRequestAsync()
        {
            if (Options.LogoutResponsePath.HasValue && Options.LogoutResponsePath == Request.Path)
            {
                return await HandleLogoutResponse();
            }
            if (Options.LogoutRequestPath.HasValue && Options.LogoutRequestPath == Request.Path)
            {
                return await HandleLogoutRequest();
            }
            return await base.HandleRequestAsync();
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            properties = properties ?? new AuthenticationProperties();
            // Get the post redirect URI.
            if (string.IsNullOrWhiteSpace(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }
            // generate AuthnRequest ID
            var authnRequestID = GenerateID();
            properties.Items[nameof(authnRequestID)] = authnRequestID;
            string authnRequest;
            authnRequest = new MPassSamlProtocolMessage(Clock)
            {
                IssuerAddress = Options.SamlLoginDestination,
                RequestIssuer = Options.SamlRequestIssuer,
                RequestID = authnRequestID,
                RelayState = Options.StateDataFormat.Protect(properties),
                ServiceCertificate = Options.ServiceCertificate
            }.BuildAuthRequestForm(Options.ServiceRootUrl + Options.CallbackPath);
            //configuring response
            await SetResponseForm(authnRequest);
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            string sessionIndex = null;
            ClaimsIdentity identity = null;
            AuthenticationProperties relayState = null;
            if (HttpMethods.IsPost(Request.Method) && Request.HasFormContentType)
            {
                var form = await Request.ReadFormAsync();
                if (form.ContainsKey(MPassSamlDefaults.SAMLResponse))
                {
                    relayState = Options.StateDataFormat.Unprotect(form[MPassSamlDefaults.RelayState]);
                    identity = new MPassSamlProtocolMessage(Clock)
                    {
                        RequestID = relayState.Items["authnRequestID"],
                        IdentityProviderCertificate = Options.IdpCertificate,
                        SamlMessageTimeout = Options.SamlMessageTimeout,
                        RequestIssuer = Options.SamlRequestIssuer
                    }.LoadAndVerifyLoginResponse(form[MPassSamlDefaults.SAMLResponse], Options.ServiceRootUrl + Options.CallbackPath, out sessionIndex);
                }
            }
            if (identity == null)
            {
                return HandleRequestResult.Fail("Invalid MPass response");
            }
            identity.AddClaim(new Claim(MPassSamlDefaults.SessionIndex, sessionIndex));
            return HandleRequestResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity),
                new AuthenticationProperties() { RedirectUri = relayState.RedirectUri }, Scheme.Name));
        }

        public async Task<bool> HandleLogoutResponse()
        {
            if (HttpMethods.IsPost(Request.Method) && Request.HasFormContentType)
            {
                var form = await Request.ReadFormAsync();
                if (form.ContainsKey(MPassSamlDefaults.SAMLResponse))
                {
                    var relayState = Options.StateDataFormat.Unprotect(form[MPassSamlDefaults.RelayState]);
                    new MPassSamlProtocolMessage(Clock)
                    {
                        IdentityProviderCertificate = Options.IdpCertificate,
                        SamlMessageTimeout = Options.SamlMessageTimeout,
                        RequestID = relayState.Items["logoutRequestID"]
                    }.LoadAndVerifyLogoutResponse(form[MPassSamlDefaults.SAMLResponse], Options.ServiceRootUrl + Options.LogoutResponsePath);
                    Response.Redirect(relayState.RedirectUri);
                    return true;
                }
            }
            return false;
        }

        public async Task<bool> HandleLogoutRequest()
        {
            string logoutRequestID = null;
            string relayState = null;
            if (HttpMethods.IsPost(Request.Method) && Request.HasFormContentType)
            {
                var form = await Request.ReadFormAsync();
                if (form.ContainsKey(MPassSamlDefaults.SAMLRequest))
                {
                    logoutRequestID = new MPassSamlProtocolMessage(Clock)
                    {
                        IdentityProviderCertificate = Options.IdpCertificate,
                        SamlMessageTimeout = Options.SamlMessageTimeout,
                    }.LoadAndVerifyLogoutRequest(form[MPassSamlDefaults.SAMLRequest], Options.ServiceRootUrl + Options.LogoutRequestPath, Context.User?.Identity?.Name, Context.User?.FindFirst(MPassSamlDefaults.SessionIndex)?.Value);
                }
                relayState = form[MPassSamlDefaults.RelayState];
            }
            await Response.HttpContext.SignOutAsync(Options.SignOutScheme);

            var logoutResponse = new MPassSamlProtocolMessage(Clock)
            {
                RelayState = relayState,
                RequestID = logoutRequestID,
                IssuerAddress = Options.SamlLogoutDestination,
                RequestIssuer = Options.SamlRequestIssuer,
                ServiceCertificate = Options.ServiceCertificate
            }.BuildLogoutResponse(GenerateID());
            await SetResponseForm(logoutResponse);
            return true;
        }

        //prepare and send logoutRequest to MPass
        public async Task SignOutAsync(AuthenticationProperties properties)
        {
            if (!Context.User.Identity.IsAuthenticated) return;
            properties = properties ?? new AuthenticationProperties();
            // Get the post redirect URI.
            if (string.IsNullOrWhiteSpace(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }
            var logoutRequestID = GenerateID();
            properties.Items[nameof(logoutRequestID)] = logoutRequestID;
            var logoutRequest = new MPassSamlProtocolMessage(Clock)
            {
                RequestID = logoutRequestID,
                IssuerAddress = Options.SamlLogoutDestination,
                RequestIssuer = Options.SamlRequestIssuer,
                ServiceCertificate = Options.ServiceCertificate,
                RelayState = Options.StateDataFormat.Protect(properties)
            }.BuildLogoutRequest(Context.User?.Identity?.Name, Context.User.FindFirst(MPassSamlDefaults.SessionIndex)?.Value);
            await SetResponseForm(logoutRequest);
        }

        private static string GenerateID() => "_" + Guid.NewGuid();

        private async Task SetResponseForm(string form)
        {
            var buffer = Encoding.UTF8.GetBytes(form);
            Response.ContentLength = buffer.Length;
            Response.ContentType = "text/html;charset=UTF-8";
            Response.Headers[HeaderNames.CacheControl] = "no-cache";
            Response.Headers[HeaderNames.Pragma] = "no-cache";
            Response.Headers[HeaderNames.Expires] = HeaderValueEpocDate;
            await Response.Body.WriteAsync(buffer, 0, buffer.Length);
        }
    }
}
