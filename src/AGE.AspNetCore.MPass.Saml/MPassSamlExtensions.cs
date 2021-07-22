using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System;
using System.Collections.Generic;
using Microsoft.Extensions.Diagnostics.HealthChecks;

namespace AGE.AspNetCore.MPass.Saml
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
            builder.Services.TryAddSingleton<IPostConfigureOptions<MPassSamlOptions>, MPassSamlPostConfigureOptions>();
            return builder.AddRemoteScheme<MPassSamlOptions, MPassSamlHandler>(authenticationScheme, displayName, configureOptions);
        }

        public static IHealthChecksBuilder AddMPassSamlHealthCheck(this IHealthChecksBuilder builder, HealthStatus? failureStatus = default, IEnumerable<string> tags = default)
        {
            return builder.AddMPassSamlHealthCheck(MPassSamlDefaults.AuthenticationScheme, failureStatus, tags);
        }

        public static IHealthChecksBuilder AddMPassSamlHealthCheck(this IHealthChecksBuilder builder, string name, HealthStatus? failureStatus = default, IEnumerable<string> tags = default)
        {
            if (String.IsNullOrWhiteSpace(name))
            {
                throw new ArgumentException("Please provide a configuration name, such as MPassSamlDefaults.AuthenticationScheme", nameof(name));
            }

            builder.Services.TryAddSingleton<MPassSamlHealthCheck>();
            return builder.AddCheck<MPassSamlHealthCheck>(name, failureStatus, tags);
        }
    }
}
