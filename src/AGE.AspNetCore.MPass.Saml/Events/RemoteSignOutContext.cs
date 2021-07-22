using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AGE.AspNetCore.MPass.Saml.Events
{
    public class RemoteSignOutContext : RemoteAuthenticationContext<MPassSamlOptions>
    {
        public RemoteSignOutContext(HttpContext context, AuthenticationScheme scheme, MPassSamlOptions options, MPassSamlProtocolMessage message)
            : base(context, scheme, options, new AuthenticationProperties()) =>
            ProtocolMessage = message;

        public MPassSamlProtocolMessage ProtocolMessage { get; set; }
    }
}
