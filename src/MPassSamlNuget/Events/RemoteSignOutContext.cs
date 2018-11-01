using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace MPassSamlNuget.Events
{
    public class RemoteSignOutContext : RemoteAuthenticationContext<MPassSamlOptions>
    {
        public RemoteSignOutContext(HttpContext context, AuthenticationScheme scheme, MPassSamlOptions options)
            : base(context, scheme, options, new AuthenticationProperties())
        { }

    }
}
