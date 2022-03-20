using Azure.Core;
using System;

namespace IdentityModel.AspNetCore.AccessTokenManagement.Azure
{
    /// <summary>
    ///     Azure Key Vault options
    /// </summary>
    public class KeyVaultOptions
    {
        /// <summary>
        ///  Azure Key Vault Url
        /// </summary>
        public Uri? Url { get; set; }

        /// <summary>
        ///  Azure Key Vault credentials(client, certificate, default, etc.)
        /// </summary>
        public TokenCredential? Credential { get; set; }
    }
}
