using Microsoft.AspNetCore.Authentication;
using System;
using System.Threading.Tasks;

namespace AGE.AspNetCore.MPass.Saml.Events
{
    public class MPassSamlEvents : RemoteAuthenticationEvents
    {
        public Func<RemoteSignOutContext, Task> OnRemoteSignOut { get; set; } = context => Task.CompletedTask;

        public Func<RemoteSignOutContext, Task> OnSignedOutCallbackRedirect { get; set; } = context => Task.CompletedTask;

        public virtual Task RemoteSignOut(RemoteSignOutContext context) => OnRemoteSignOut(context);

        public virtual Task SignedOutCallbackRedirect(RemoteSignOutContext context) => OnSignedOutCallbackRedirect(context);
    }
}
