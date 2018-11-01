using Microsoft.AspNetCore.Authentication;
using System;
using System.Threading.Tasks;

namespace MPassSamlNuget.Events
{
    public class MPassSamlEvents : RemoteAuthenticationEvents
    {
        /// <summary>
        /// Invoked when a request is received on the LogoutRequestPath.
        /// </summary>
        public Func<RemoteSignOutContext, Task> OnRemoteSignOut { get; set; } = context => Task.CompletedTask;

        /// <summary>
        /// Invoked before redirecting to the <see cref="OpenIdConnectOptions.SignedOutRedirectUri"/> at the end of a remote sign-out flow.
        /// </summary>
        public Func<RemoteSignOutContext, Task> OnSignedOutCallbackRedirect { get; set; } = context => Task.CompletedTask;

        public virtual Task RemoteSignOut(RemoteSignOutContext context) => OnRemoteSignOut(context);

        public virtual Task SignedOutCallbackRedirect(RemoteSignOutContext context) => OnSignedOutCallbackRedirect(context);
    }
}
