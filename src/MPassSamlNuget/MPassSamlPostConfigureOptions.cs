using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;
using System.Text;

namespace MPassSamlNuget
{
    public class MPassSamlPostConfigureOptions : IPostConfigureOptions<MPassSamlOptions>
    {
        private class StringSerializer : IDataSerializer<string>
        {
            public string Deserialize(byte[] data)
            {
                return Encoding.UTF8.GetString(data);
            }

            public byte[] Serialize(string model)
            {
                return Encoding.UTF8.GetBytes(model);
            }
        }

        private readonly IDataProtectionProvider dataProtectionProvider;

        public MPassSamlPostConfigureOptions(IDataProtectionProvider dataProtectionProvider)
        {
            this.dataProtectionProvider = dataProtectionProvider;
        }

        public void PostConfigure(string name, MPassSamlOptions options)
        {
            options.DataProtectionProvider = options.DataProtectionProvider ?? dataProtectionProvider;

            if (options.StateDataFormat == null)
            {
                var dataProtector = options.DataProtectionProvider.CreateProtector(typeof(MPassSamlHandler).FullName);
                options.StateDataFormat = new SecureDataFormat<string>(new StringSerializer(), dataProtector);
            }
        }
    }
}
