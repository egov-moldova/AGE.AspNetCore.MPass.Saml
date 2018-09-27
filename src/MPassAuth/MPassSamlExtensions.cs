using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;

namespace MPassAuth
{
    public static class MPassSamlExtensions
    {
        public static AuthenticationBuilder AddMPassSaml(this AuthenticationBuilder builder) 
            => builder.AddMPassSaml(MPassSamlDefaults.AuthenticationScheme, _ => { });

        public static AuthenticationBuilder AddMPassSaml(this AuthenticationBuilder builder, Action<MPassSamlOptions> configureOptions)
            => builder.AddMPassSaml(MPassSamlDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddMPassSaml(this AuthenticationBuilder builder, string authenticationScheme, Action<MPassSamlOptions> configureOptions)
            => builder.AddMPassSaml(authenticationScheme, MPassSamlDefaults.DisplayName, configureOptions);

        public static AuthenticationBuilder AddMPassSaml(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<MPassSamlOptions> configureOptions)
        {
            builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<MPassSamlOptions>, MPassSamlPostConfigureOptions>());
            return builder.AddRemoteScheme<MPassSamlOptions, MPassSamlHandler>(authenticationScheme, displayName, configureOptions);
        }
    }
}
