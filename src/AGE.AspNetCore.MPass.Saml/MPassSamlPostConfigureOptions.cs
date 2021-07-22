using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System;
using System.IO;
using System.Security.Cryptography;
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
            options.DataProtectionProvider ??= dataProtectionProvider;

            if (string.IsNullOrEmpty(options.SignOutScheme))
            {
                options.SignOutScheme = options.SignInScheme;
            }

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(typeof(MPassSamlHandler).FullName);
                options.StateDataFormat = new PropertiesDataFormat(dataProtector);
            }

            if (options.ServiceCertificate == null)
            {
                options.ServiceCertificate = LoadPrivateCertificate(options.ServiceCertificatePath, options.ServiceCertificatePassword);
                if (options.ServiceCertificate == null)
                {
                    throw new ApplicationException("Invalid service certificate path or password");
                }
            }

            if (options.IdpCertificate == null)
            {
                options.IdpCertificate = LoadPublicCertificate(options.IdentityProviderCertificatePath);
                if (options.IdpCertificate == null)
                {
                    throw new ApplicationException("Invalid identity provider certificate path");
                }
            }
        }

        private static X509Certificate2 LoadPublicCertificate(string certificatePath)
        {
            if (string.IsNullOrWhiteSpace(certificatePath)) return null;

            // load file directly
            if (File.Exists(certificatePath))
            {
                return new X509Certificate2(certificatePath);
            }

            // load from a mounted Kubernetes secret
            if (!Directory.Exists(certificatePath)) return null;
            var certificateFile = Path.Combine(certificatePath, "tls.crt");
            if (!File.Exists(certificateFile)) return null;
            return new X509Certificate2(certificateFile);
        }

        private static X509Certificate2 LoadPrivateCertificate(string certificatePath, string certificatePassword)
        {
            if (string.IsNullOrWhiteSpace(certificatePath)) return null;
            
            // load PFX
            if (File.Exists(certificatePath) && !string.IsNullOrWhiteSpace(certificatePassword))
            {
                return new X509Certificate2(certificatePath, certificatePassword, X509KeyStorageFlags.MachineKeySet);
            }

            // load from a mounted Kubernetes secret
            if (!Directory.Exists(certificatePath)) return null;
            var certificateFile = Path.Combine(certificatePath, "tls.crt");
            var keyFile = Path.Combine(certificatePath, "tls.key");
            if (!File.Exists(certificateFile) || !File.Exists(keyFile)) return null;

            using var publicCertificate = new X509Certificate2(certificateFile);

            var privateKeyLines = File.ReadAllLines(keyFile);
            if (privateKeyLines.Length < 3) return null;
            var privateKeyBytes = Convert.FromBase64String(String.Concat(privateKeyLines[1..^1]));

            if (privateKeyLines[0].Contains("EC PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            {
                using var algorithm = ECDsa.Create();
                algorithm.ImportECPrivateKey(privateKeyBytes, out _);
                return new X509Certificate2(publicCertificate.CopyWithPrivateKey(algorithm).Export(X509ContentType.Pfx));
            }
            if (privateKeyLines[0].Contains("RSA PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            {
                using var algorithm = RSA.Create();
                algorithm.ImportRSAPrivateKey(privateKeyBytes, out _);
                return new X509Certificate2(publicCertificate.CopyWithPrivateKey(algorithm).Export(X509ContentType.Pfx));
            }
            if (privateKeyLines[0].Contains("DSA PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
            {
                using var algorithm = DSA.Create();
                algorithm.ImportPkcs8PrivateKey(privateKeyBytes, out _);
                return new X509Certificate2(publicCertificate.CopyWithPrivateKey(algorithm).Export(X509ContentType.Pfx));
            }

            return null;
        }
    }
}
