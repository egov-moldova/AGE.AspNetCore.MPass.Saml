using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace MPassSamlNuget
{
    public class MPassSamlHandler : RemoteAuthenticationHandler<MPassSamlOptions>, IAuthenticationSignOutHandler
    {
        private const string HeaderValueEpocDate = "Thu, 01 Jan 1970 00:00:00 GMT";
        private MPassSamlOptions options;
        private X509Certificate2 serviceCertificate { get; }
        private X509Certificate2 idpCertificate { get; }
        public MPassSamlHandler(IOptionsMonitor<MPassSamlOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
         : base(options, logger, encoder, clock)
        {
            this.options = options.CurrentValue;
            serviceCertificate = new X509Certificate2(this.options.ServiceCertificate, this.options.ServiceCertificatePassword, X509KeyStorageFlags.MachineKeySet);
            idpCertificate = new X509Certificate2(this.options.IdentityProviderCertificate);
        }

        public override async Task<bool> HandleRequestAsync()
        {
            if (options.LogoutResponsePath.HasValue && options.LogoutResponsePath == Request.Path)
            {
                return await HandleLogoutResponse();
            }
            if (options.LogoutRequestPath.HasValue && options.LogoutRequestPath == Request.Path)
            {
                return await HandleLogoutRequest();
            }
            return await base.HandleRequestAsync();
        }

        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            Response.StatusCode = 403;
            Response.Redirect(properties.RedirectUri);
            return Task.CompletedTask;
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
            var authnRequestID = "_" + Guid.NewGuid();
            properties.Items[nameof(authnRequestID)] = authnRequestID;
            string authnRequest;
            try
            {
                authnRequest = new MPassSamlProtocolMessage
                {
                    IssuerAddress = options.SamlLoginDestination,
                    RequestIssuer = options.SamlRequestIssuer,
                    RequestID = authnRequestID,
                    RelayState = options.StateDataFormat.Protect(JsonConvert.SerializeObject(properties.Items)),
                    SamlParameter = "SAMLRequest",
                    ServiceCertificate = serviceCertificate
                }.BuildAuthnRequestForm(options.ServiceRootUrl + options.CallbackPath);
            }
            catch (ApplicationException applicationEx)
            {
                throw applicationEx;
            }
            catch (Exception ex)
            {
                throw ex;
            }
            //configuring response
            await SetResponseForm(authnRequest);
        }

        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            string sessionIndex = null;
            ClaimsIdentity identity = null;
            JObject relayState = null;
            if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase) && Request.HasFormContentType)
            {
                var form = await Request.ReadFormAsync();
                relayState = JObject.Parse(options.StateDataFormat.Unprotect(form["RelayState"][0]));
                if (form.ContainsKey("SAMLResponse"))
                {
                    try
                    {
                        identity = new MPassSamlProtocolMessage
                        {
                            RequestID = relayState["authnRequestID"].ToString(),
                            IdentityProviderCertificate = idpCertificate,
                            SamlMessageTimeout = TimeSpan.Parse(options.SamlMessageTimeout),
                            SamlResponse = form["SAMLResponse"],
                            RequestIssuer = options.SamlRequestIssuer
                        }.LoadAndVerifyLoginResponse(options.ServiceRootUrl + options.CallbackPath, out sessionIndex);
                    }
                    //catch (ApplicationException appEx)
                    //{
                    //    throw appEx;
                    //}
                    catch (Exception ex)
                    {
                        throw ex;
                    }
                }
            }
            if (identity == null)
            {
                return HandleRequestResult.Fail("Invalid MPass response");
            }
            identity.AddClaim(new Claim("SessionIndex", sessionIndex));
            identity.AddClaim(new Claim("Role", "administrator"));
            return HandleRequestResult.Success(new AuthenticationTicket(new ClaimsPrincipal(identity),
                new AuthenticationProperties() { RedirectUri = relayState[".redirect"].ToString() }, Scheme.Name));
        }

        public async Task<bool> HandleLogoutResponse()
        {
            if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase) && Request.HasFormContentType)
            {
                var form = await Request.ReadFormAsync();
                var relayState = JObject.Parse(options.StateDataFormat.Unprotect(form["RelayState"][0]));
                if (form.ContainsKey("SAMLResponse"))
                {
                    new MPassSamlProtocolMessage
                    {
                        SamlResponse = form["SAMLResponse"],
                        IdentityProviderCertificate = idpCertificate,
                        SamlMessageTimeout = TimeSpan.Parse(options.SamlMessageTimeout),
                        RequestID = relayState["logoutRequestID"].ToString()
                    }.LoadAndVerifyLogoutResponse(options.ServiceRootUrl + options.LogoutResponsePath);
                    Response.Redirect(relayState[".redirect"].ToString());
                    return true;
                }
                else return false;
            }
            return false;
        }

        public async Task<bool> HandleLogoutRequest()
        {
            string logoutRequestID = null;
            if (string.Equals(Request.Method, "POST", StringComparison.OrdinalIgnoreCase) && Request.HasFormContentType)
            {
                var form = await Request.ReadFormAsync();
                if (form.ContainsKey("SAMLRequest"))
                {
                    new MPassSamlProtocolMessage
                    {
                        RequestIssuer = form["SAMLRequest"].ToString(),
                        IdentityProviderCertificate = idpCertificate,
                        SamlMessageTimeout = TimeSpan.Parse(options.SamlMessageTimeout),
                    }.LoadAndVerifyLogoutRequest(options.ServiceRootUrl + options.LogoutRequestPath, Context.User.Identity.Name,
                                                 Context.User.FindFirst("SessionIndex")?.Value, out logoutRequestID);
                }
            }
            await Response.HttpContext.SignOutAsync(Options.SignOutScheme);
            var logoutResponseID = "_" + Guid.NewGuid();
            var logoutResponse = new MPassSamlProtocolMessage
            {
                RelayState = options.StateDataFormat.Protect(logoutResponseID),
                RequestID = logoutRequestID,
                SamlParameter = "SAMLResponse",
                IssuerAddress = options.SamlLogoutDestination,
                RequestIssuer = options.SamlRequestIssuer,
                ServiceCertificate = serviceCertificate
            }.BuildLogoutResponse();
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
            var logoutRequestID = "_" + Guid.NewGuid();
            properties.Items[nameof(logoutRequestID)] = logoutRequestID;
            var logoutRequest = new MPassSamlProtocolMessage
            {
                RequestID = logoutRequestID,
                IssuerAddress = options.SamlLogoutDestination,
                RequestIssuer = options.SamlRequestIssuer,
                SamlParameter = "SAMLRequest",
                ServiceCertificate = serviceCertificate,
                RelayState = options.StateDataFormat.Protect(JsonConvert.SerializeObject(properties.Items))
            }.BuildLogoutRequest(Context.User.Identity.Name, Context.User.FindFirst("SessionIndex").Value);
            await SetResponseForm(logoutRequest);
        }

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
