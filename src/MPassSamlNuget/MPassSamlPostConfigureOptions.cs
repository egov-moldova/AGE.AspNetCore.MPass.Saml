using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System;
using System.Security.Cryptography.X509Certificates;

namespace AGE.AspNetCore.MPass.Saml
{
    public class MPassSamlPostConfigureOptions : IPostConfigureOptions<MPassSamlOptions>
    {
        private readonly IDataProtectionProvider dataProtectionProvider;

        public MPassSamlPostConfigureOptions(IDataProtectionProvider dataProtectionProvider)
        {
            this.dataProtectionProvider = dataProtectionProvider;
        }

        public void PostConfigure(string name, MPassSamlOptions options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? dataProtectionProvider;

            if (string.IsNullOrEmpty(options.SignOutScheme))
            {
                options.SignOutScheme = options.SignInScheme;
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(typeof(MPassSamlHandler).FullName);
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (!string.IsNullOrEmpty(options.ServiceCertificatePath) && !string.IsNullOrEmpty(options.ServiceCertificatePassword))
            {
                options.ServiceCertificate = new X509Certificate2(options.ServiceCertificatePath, options.ServiceCertificatePassword, X509KeyStorageFlags.MachineKeySet);
            }
            else
            {
                throw new ApplicationException("Invalid service certificate path or password");
            }

            if (!string.IsNullOrEmpty(options.IdentityProviderCertificatePath))
            {
                options.IdpCertificate = new X509Certificate2(options.IdentityProviderCertificatePath);
            }
            else
            {
                throw new ApplicationException("Invalid identity provider path ");
            }
        }
    }
}
