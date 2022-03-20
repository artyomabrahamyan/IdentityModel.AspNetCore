using Azure;
using Azure.Security.KeyVault.Secrets;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace IdentityModel.AspNetCore.AccessTokenManagement.Azure
{
    /// <summary>
    ///     Client access token cache using Azure Key Vault SecretClient.
    /// </summary>
    public class KeyVaultClientAccessTokenCache : IClientAccessTokenCache
    {
        private readonly SecretClient _secretClient;
        private readonly ILogger<KeyVaultClientAccessTokenCache> _logger;
        private readonly ClientAccessTokenManagementOptions _options;
        private const string KeySeparator = "--";

        /// <summary>
        /// ctor
        /// </summary>
        /// <param name="logger"></param>
        /// <param name="secretClient"></param>
        /// <param name="options"></param>
        public KeyVaultClientAccessTokenCache(
            ILogger<KeyVaultClientAccessTokenCache> logger,
            SecretClient secretClient,
            ClientAccessTokenManagementOptions options)
        {
            _secretClient = secretClient;
            _options = options;
            _logger = logger;
        }

        /// <inheritdoc/>
        public async Task<ClientAccessToken?> GetAsync(
            string clientName, 
            ClientAccessTokenParameters parameters,
            CancellationToken cancellationToken = default)
        {
            var cacheKey = GenerateCacheKey(clientName, parameters);
            Response<KeyVaultSecret>? response;

            try
            {
                response = await _secretClient.GetSecretAsync(cacheKey, cancellationToken: cancellationToken);
            }
            catch (RequestFailedException e) when (e.Status == StatusCodes.Status404NotFound) 
            {
                _logger.LogDebug("Cache miss for access token for client: {clientName}", clientName);
                return null;
            }

            if (response!.Value.Properties.ExpiresOn.GetValueOrDefault() <= DateTimeOffset.UtcNow)
            {
                _logger.LogDebug("Cached access token for client: {clientName} is expired or does not have proper expiration", clientName);
                await DeleteAsync(clientName, parameters, cancellationToken);
                return null;
            }

            return new ClientAccessToken
            {
                AccessToken = response.Value.Value,
                Expiration = response.Value.Properties.ExpiresOn!.Value
            };
        }

        /// <inheritdoc/>
        public async Task DeleteAsync(
            string clientName, 
            ClientAccessTokenParameters parameters, 
            CancellationToken cancellationToken = default)
        {
            if (clientName is null) throw new ArgumentNullException(nameof(clientName));

            var cacheKey = GenerateCacheKey(clientName, parameters);

            var operation = await _secretClient.StartDeleteSecretAsync(cacheKey, cancellationToken);
            await operation.WaitForCompletionAsync(cancellationToken);
            await _secretClient.PurgeDeletedSecretAsync(cacheKey, cancellationToken);
        }

        /// <inheritdoc/>
        public async Task SetAsync(
            string clientName, 
            string accessToken, 
            int expiresIn, 
            ClientAccessTokenParameters parameters, 
            CancellationToken cancellationToken = default)
        {

            if (clientName is null) throw new ArgumentNullException(nameof(clientName));

            var expiration = DateTimeOffset.UtcNow.AddSeconds(expiresIn);
            var cacheExpiration = expiration.AddSeconds(-_options.CacheLifetimeBuffer);

            _logger.LogDebug("Caching access token for client: {clientName}. Expiration: {expiration}", clientName, cacheExpiration);

            var cacheKey = GenerateCacheKey(clientName, parameters);

            var kvSecret = new KeyVaultSecret(cacheKey, accessToken);
            kvSecret.Properties.ExpiresOn = expiration;
            await _secretClient.SetSecretAsync(kvSecret, cancellationToken);
        }

        private string GenerateCacheKey(
            string clientName,
            ClientAccessTokenParameters? parameters = null) =>
                $"{nameof(IdentityModel)}{KeySeparator}{nameof(AccessTokenManagement)}{KeySeparator}{clientName}{KeySeparator}{parameters?.Resource ?? string.Empty}";
    }
}
