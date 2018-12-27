using System;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using AGE.AspNetCore.MPass.Saml.Events;

namespace AGE.AspNetCore.MPass.Saml
{
    public class MPassSamlHandler : RemoteAuthenticationHandler<MPassSamlOptions>, IAuthenticationSignOutHandler
    {
        private const string HeaderValueEpocDate = "Thu, 01 Jan 1970 00:00:00 GMT";

        public MPassSamlHandler(IOptionsMonitor<MPassSamlOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
         : base(options, logger, encoder, clock)
        {
        }

        protected new MPassSamlEvents Events
        {
            get { return (MPassSamlEvents)base.Events; }
            set { base.Events = value; }
        }

        protected override Task<object> CreateEventsAsync() => Task.FromResult<object>(new MPassSamlEvents());


        public override Task<bool> HandleRequestAsync()
        {
            if (Options.LogoutResponsePath.HasValue && Options.LogoutResponsePath == Request.Path)
            {
                return HandleLogoutResponse();
            }
            if (Options.LogoutRequestPath.HasValue && Options.LogoutRequestPath == Request.Path)
            {
                return HandleLogoutRequest();
            }
            return base.HandleRequestAsync();
        }

        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // Get the post redirect URI.
            if (string.IsNullOrWhiteSpace(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }
            // generate AuthnRequest ID
            var authnRequestID = GenerateID();
            properties.Items[nameof(authnRequestID)] = authnRequestID;
            var authnRequest = new MPassSamlProtocolMessage(Clock)
            {
                IssuerAddress = Options.SamlLoginDestination,
                RequestIssuer = Options.SamlRequestIssuer,
                RequestID = authnRequestID,
                RelayState = Options.StateDataFormat.Protect(properties),
                ServiceCertificate = Options.ServiceCertificate
            }.BuildAuthmRequestForm(Options.ServiceRootUrl + Options.CallbackPath);
            await SetResponseForm(authnRequest);
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            if (!HttpMethods.IsPost(Request.Method) || !Request.HasFormContentType)
            {
                return HandleRequestResult.Fail("No MPass response");
            }
            var form = await Request.ReadFormAsync();
            if (!form.ContainsKey(MPassSamlDefaults.SAMLResponse))
            {
                return HandleRequestResult.Fail("No SAML response");
            }
            var relayState = Options.StateDataFormat.Unprotect(form[MPassSamlDefaults.RelayState]);
            return new MPassSamlProtocolMessage(Clock)
            {
                RequestID = relayState.Items["authnRequestID"],
                IdentityProviderCertificate = Options.IdpCertificate,
                SamlMessageTimeout = Options.SamlMessageTimeout,
                RequestIssuer = Options.SamlRequestIssuer
            }.LoadAndVerifyLoginResponse(form[MPassSamlDefaults.SAMLResponse], Options.ServiceRootUrl + Options.CallbackPath, relayState.RedirectUri, Scheme.Name);
        }

        public async Task<bool> HandleLogoutResponse()
        {
            AuthenticationProperties relayState = null;
            if (HttpMethods.IsPost(Request.Method) && Request.HasFormContentType)
            {
                var form = await Request.ReadFormAsync();
                if (form.ContainsKey(MPassSamlDefaults.SAMLResponse) && form.ContainsKey(MPassSamlDefaults.RelayState))
                {
                    relayState = Options.StateDataFormat.Unprotect(form[MPassSamlDefaults.RelayState]);
                    new MPassSamlProtocolMessage(Clock)
                    {
                        IdentityProviderCertificate = Options.IdpCertificate,
                        SamlMessageTimeout = Options.SamlMessageTimeout,
                        RequestID = relayState.Items["logoutRequestID"]
                    }.LoadAndVerifyLogoutResponse(form[MPassSamlDefaults.SAMLResponse], Options.ServiceRootUrl + Options.LogoutResponsePath);
                }
            }

            var remoteSignOutContext = new RemoteSignOutContext(Context, Scheme, Options)
            {
                Properties = relayState,
            };

            await Events.SignedOutCallbackRedirect(remoteSignOutContext);
            if (remoteSignOutContext.Result != null)
            {
                if (remoteSignOutContext.Result.Handled)
                {
                    return true;
                }
                if (remoteSignOutContext.Result.Skipped)
                {
                    return false;
                }
                if (remoteSignOutContext.Result.Failure != null)
                {
                    throw new InvalidOperationException("An error was returned from SignedOutCallbackRedirect event.", remoteSignOutContext.Result.Failure);
                }
            }

            if (!string.IsNullOrEmpty(relayState?.RedirectUri))
            {
                Response.Redirect(relayState.RedirectUri);
            }
            return true;
        }

        public async Task<bool> HandleLogoutRequest()
        {
            if (!HttpMethods.IsPost(Request.Method) || !Request.HasFormContentType) return false;
            var form = await Request.ReadFormAsync();
            if (!form.ContainsKey(MPassSamlDefaults.SAMLRequest)) return false;

            var user = await Context.AuthenticateAsync(Options.SignOutScheme);
            var expectedNameID = user?.Principal?.Identity?.Name;
            var expectedSessionIndex = user?.Principal?.FindFirst(MPassSamlDefaults.SessionIndex)?.Value;

            var verifyResponse = new MPassSamlProtocolMessage(Clock)
            {
                IdentityProviderCertificate = Options.IdpCertificate,
                SamlMessageTimeout = Options.SamlMessageTimeout,
            }.LoadAndVerifyLogoutRequest(form[MPassSamlDefaults.SAMLRequest], Options.ServiceRootUrl + Options.LogoutRequestPath, expectedNameID, expectedSessionIndex);
            if (verifyResponse.Error != null) return false;

            var logoutRequestID = verifyResponse.LogoutRequestID;
            var relayState = form[MPassSamlDefaults.RelayState];

            var remoteSignOutContext = new RemoteSignOutContext(Context, Scheme, Options);
            await Events.RemoteSignOut(remoteSignOutContext);

            if (remoteSignOutContext.Result != null)
            {
                if (remoteSignOutContext.Result.Handled)
                {
                    await SetRemoteLogoutResponse(logoutRequestID, relayState);
                    return true;
                }
                if (remoteSignOutContext.Result.Skipped)
                {
                    return false;
                }
                if (remoteSignOutContext.Result.Failure != null)
                {
                    throw new InvalidOperationException("An error was returned from RemoteSignOut event.", remoteSignOutContext.Result.Failure);
                }
            }
            await Context.SignOutAsync(Options.SignOutScheme);

            await SetResponseForm(new MPassSamlProtocolMessage(Clock)
            {
                RelayState = relayState,
                RequestID = logoutRequestID,
                IssuerAddress = Options.SamlLogoutDestination,
                RequestIssuer = Options.SamlRequestIssuer,
                ServiceCertificate = Options.ServiceCertificate
            }.BuildLogoutResponse(GenerateID()));
            return true;
        }

        private Task SetRemoteLogoutResponse(string logoutRequestID, string relayState)
        {
            return SetResponseForm(new MPassSamlProtocolMessage(Clock)
            {
                RelayState = relayState,
                RequestID = logoutRequestID,
                IssuerAddress = Options.SamlLogoutDestination,
                RequestIssuer = Options.SamlRequestIssuer,
                ServiceCertificate = Options.ServiceCertificate
            }.BuildLogoutResponse(GenerateID()));
        }

        //prepare and send logoutRequest to MPass
        public async Task SignOutAsync(AuthenticationProperties properties)
        {
            var target = ResolveTarget(Options.ForwardSignOut);
            if (target != null)
            {
                await Context.SignOutAsync(target, properties);
                return;
            }

            if (!Context.User.Identity.IsAuthenticated) return;

            properties = properties ?? new AuthenticationProperties();
            // Get the post redirect URI.
            if (string.IsNullOrWhiteSpace(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }
            var logoutRequestID = GenerateID();
            properties.Items[nameof(logoutRequestID)] = logoutRequestID;
            await SetResponseForm(new MPassSamlProtocolMessage(Clock)
            {
                RequestID = logoutRequestID,
                IssuerAddress = Options.SamlLogoutDestination,
                RequestIssuer = Options.SamlRequestIssuer,
                ServiceCertificate = Options.ServiceCertificate,
                RelayState = Options.StateDataFormat.Protect(properties)
            }.BuildLogoutRequest(Context.User?.Identity?.Name, Context.User.FindFirst(MPassSamlDefaults.SessionIndex)?.Value));
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
