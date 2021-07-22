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
using Microsoft.AspNetCore.WebUtilities;

namespace AGE.AspNetCore.MPass.Saml
{
    public class MPassSamlHandler : RemoteAuthenticationHandler<MPassSamlOptions>, IAuthenticationSignOutHandler
    {
        public MPassSamlHandler(IOptionsMonitor<MPassSamlOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
         : base(options, logger, encoder, clock)
        {
        }

        protected new MPassSamlEvents Events
        {
            get => (MPassSamlEvents)base.Events;
            set => base.Events = value;
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

        /// <summary>
        /// Responds to a 401 Challenge. Sends an AuthnRequest to MPass.
        /// </summary>
        protected override async Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            // Get the post redirect URI.
            if (string.IsNullOrWhiteSpace(properties.RedirectUri))
            {
                properties.RedirectUri = CurrentUri;
            }

            await SetAuthnRequest(properties);
        }

        /// <summary>
        /// Handles Response from MPass.
        /// </summary>
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
            var message = new MPassSamlProtocolMessage(Clock)
            {
                RequestID = relayState.GetString(MPassSamlAuthenticationProperties.AuthnRequestIDKey),
                IdentityProviderCertificate = Options.IdpCertificate,
                SamlMessageTimeout = Options.SamlMessageTimeout,
                RequestIssuer = Options.SamlRequestIssuer
            };
            var result = message.LoadAndVerifyLoginResponse(form[MPassSamlDefaults.SAMLResponse], 
                BuildRedirectUriIfRelative(Options.ServiceRootUrl + Options.CallbackPath), relayState.RedirectUri, Scheme.Name);
            if (result.Succeeded || Options.FailOnInvalidResponse) return result;

            var failedRedirectUri = relayState.GetString(MPassSamlAuthenticationProperties.FailedRedirectUriKey);
            var redirectUri =  failedRedirectUri ?? Options.InvalidResponseRedirectUri;
            if (!string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = BuildRedirectUriIfRelative(redirectUri);
                if (!string.IsNullOrWhiteSpace(redirectUri))
                {
                    Response.Redirect(redirectUri);
                    return HandleRequestResult.Handle();
                }
            }

            return result;
        }

        /// <summary>
        /// Redirect user to the identity provider for sign out, i.e. send LogoutRequest to MPass.
        /// </summary>
        public async Task SignOutAsync(AuthenticationProperties properties)
        {
            var target = ResolveTarget(Options.ForwardSignOut);
            if (target != null)
            {
                await Context.SignOutAsync(target, properties);
                return;
            }

            if (!Context.User.Identity.IsAuthenticated) return;

            await SetLogoutRequest(properties);
        }

        /// <summary>
        /// Handles LogoutResponse from MPass.
        /// </summary>
        public async Task<bool> HandleLogoutResponse()
        {
            MPassSamlProtocolMessage message = null;

            AuthenticationProperties relayState = null;
            if (HttpMethods.IsPost(Request.Method) && Request.HasFormContentType)
            {
                var form = await Request.ReadFormAsync();
                if (form.ContainsKey(MPassSamlDefaults.SAMLResponse) && form.ContainsKey(MPassSamlDefaults.RelayState))
                {
                    relayState = Options.StateDataFormat.Unprotect(form[MPassSamlDefaults.RelayState]);
                    message = new MPassSamlProtocolMessage(Clock)
                    {
                        IdentityProviderCertificate = Options.IdpCertificate,
                        SamlMessageTimeout = Options.SamlMessageTimeout,
                        RequestID = relayState.GetString(MPassSamlAuthenticationProperties.LogoutRequestIDKey)
                    };
                    message.LoadAndVerifyLogoutResponse(form[MPassSamlDefaults.SAMLResponse], BuildRedirectUriIfRelative(Options.ServiceRootUrl + Options.LogoutResponsePath));
                }
            }

            var remoteSignOutContext = new RemoteSignOutContext(Context, Scheme, Options, message);
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

            var redirectUri = relayState?.RedirectUri;
            if (string.IsNullOrEmpty(redirectUri))
            {
                redirectUri = BuildRedirectUriIfRelative(Options.SignedOutRedirectUri);
                if (string.IsNullOrWhiteSpace(redirectUri))
                {
                    redirectUri = CurrentUri;
                }
            }

            Response.Redirect(redirectUri);
            return true;
        }

        /// <summary>
        /// Handles LogoutRequest from MPass.
        /// </summary>
        public async Task<bool> HandleLogoutRequest()
        {
            if (!HttpMethods.IsPost(Request.Method) || !Request.HasFormContentType) return false;
            var form = await Request.ReadFormAsync();
            if (!form.ContainsKey(MPassSamlDefaults.SAMLRequest)) return false;

            var user = await Context.AuthenticateAsync(Options.SignOutScheme);
            var expectedNameID = user?.Principal?.Identity?.Name;
            var expectedSessionIndex = user?.Principal?.FindFirst(MPassSamlDefaults.SessionIndex)?.Value;

            var message = new MPassSamlProtocolMessage(Clock)
            {
                IdentityProviderCertificate = Options.IdpCertificate,
                SamlMessageTimeout = Options.SamlMessageTimeout
            };
            var verifyResponse = message.LoadAndVerifyLogoutRequest(form[MPassSamlDefaults.SAMLRequest], 
                BuildRedirectUriIfRelative(Options.ServiceRootUrl + Options.LogoutRequestPath), expectedNameID, expectedSessionIndex);
            if (verifyResponse.Error != null) return false;

            var logoutRequestID = verifyResponse.LogoutRequestID;
            var relayState = form[MPassSamlDefaults.RelayState];

            var remoteSignOutContext = new RemoteSignOutContext(Context, Scheme, Options, message);
            await Events.RemoteSignOut(remoteSignOutContext);

            if (remoteSignOutContext.Result != null)
            {
                if (remoteSignOutContext.Result.Handled)
                {
                    await SetLogoutResponse(logoutRequestID, relayState);
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

            await SetLogoutResponse(logoutRequestID, relayState);
            return true;
        }

        private Task SetAuthnRequest(AuthenticationProperties properties)
        {
            var authnRequestID = GenerateID();
            properties.SetString(MPassSamlAuthenticationProperties.AuthnRequestIDKey, authnRequestID);

            var samlProperties = properties as MPassSamlAuthenticationProperties;

            var isPassive = false;
            if (samlProperties?.IsPassive != null)
            {
                isPassive = samlProperties.IsPassive.Value;
                samlProperties.IsPassive = null;
            }

            var issuerAddress = Options.SamlLoginDestination;
            if (!string.IsNullOrWhiteSpace(samlProperties?.Language))
            {
                issuerAddress = QueryHelpers.AddQueryString(issuerAddress, 
                    MPassSamlAuthenticationProperties.LanguageKey, samlProperties.Language);
                samlProperties.Language = null;
            }

            return SetResponseForm(new MPassSamlProtocolMessage(Clock)
            {
                IssuerAddress = issuerAddress,
                RequestIssuer = Options.SamlRequestIssuer,
                RequestID = authnRequestID,
                RelayState = Options.StateDataFormat.Protect(properties),
                ServiceCertificate = Options.ServiceCertificate
            }.BuildAuthnRequest(BuildRedirectUriIfRelative(Options.ServiceRootUrl + Options.CallbackPath), isPassive));
        }

        private Task SetLogoutRequest(AuthenticationProperties properties)
        {
            if (properties == null)
            {
                properties = new AuthenticationProperties();
            }
            var logoutRequestID = GenerateID();
            properties.SetString(MPassSamlAuthenticationProperties.LogoutRequestIDKey, logoutRequestID);
            return SetResponseForm(new MPassSamlProtocolMessage(Clock)
            {
                RequestID = logoutRequestID,
                IssuerAddress = Options.SamlLogoutDestination,
                RequestIssuer = Options.SamlRequestIssuer,
                ServiceCertificate = Options.ServiceCertificate,
                RelayState = Options.StateDataFormat.Protect(properties)
            }.BuildLogoutRequest(Context.User.Identity.Name, Context.User.FindFirst(MPassSamlDefaults.SessionIndex)?.Value));
        }

        private Task SetLogoutResponse(string logoutRequestID, string relayState)
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

        private static string GenerateID() => "_" + Guid.NewGuid();

        private async Task SetResponseForm(string form)
        {
            var responseHeaders = Response.GetTypedHeaders();
            responseHeaders.CacheControl = new CacheControlHeaderValue {NoCache = true, NoStore = true};
            responseHeaders.Expires = DateTimeOffset.UnixEpoch;

            var buffer = Encoding.UTF8.GetBytes(form);
            Response.ContentType = "text/html;charset=UTF-8";
            Response.ContentLength = buffer.Length;
            await Response.Body.WriteAsync(buffer, Context.RequestAborted);
        }

        private string BuildRedirectUriIfRelative(string uri)
        {
            if (string.IsNullOrEmpty(uri))
            {
                return uri;
            }

            return !uri.StartsWith("/", StringComparison.Ordinal) ? uri : BuildRedirectUri(uri);
        }
    }
}
