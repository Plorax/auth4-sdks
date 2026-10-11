using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Auth4
{
    /// <summary>
    /// Contract for platform secure storage, such as the iOS Keychain, Android Keystore-backed
    /// encrypted storage, Windows DPAPI or a console vendor's protected save API. Implementations must
    /// encrypt at rest with an OS-protected key and must never write to PlayerPrefs, plain files or
    /// logs. Refresh tokens are persisted only when an adapter is supplied explicitly.
    /// </summary>
    public interface ISecureStorageAdapter
    {
        /// <summary>Returns the stored value, or null when the key is absent.</summary>
        Task<string> ReadAsync(string key, CancellationToken cancellationToken);

        Task WriteAsync(string key, string value, CancellationToken cancellationToken);

        Task DeleteAsync(string key, CancellationToken cancellationToken);
    }

    /// <summary>Where the client keeps its refresh credential. Selected only from the client options.</summary>
    internal interface IAuth4TokenStorage
    {
        /// <summary>True only for storage that survives the process.</summary>
        bool IsPersistent { get; }

        Task<string> LoadAsync(string key, CancellationToken cancellationToken);

        Task SaveAsync(string key, string value, CancellationToken cancellationToken);

        Task DeleteAsync(string key, CancellationToken cancellationToken);
    }

    /// <summary>Default storage. Credentials are lost when the process exits.</summary>
    internal sealed class InMemoryTokenStorage : IAuth4TokenStorage
    {
        private readonly Dictionary<string, string> _values = new Dictionary<string, string>(StringComparer.Ordinal);

        public bool IsPersistent => false;

        public Task<string> LoadAsync(string key, CancellationToken cancellationToken)
        {
            lock (_values)
            {
                return Task.FromResult(_values.TryGetValue(key, out var value) ? value : null);
            }
        }

        public Task SaveAsync(string key, string value, CancellationToken cancellationToken)
        {
            lock (_values)
            {
                _values[key] = value;
            }

            return Task.CompletedTask;
        }

        public Task DeleteAsync(string key, CancellationToken cancellationToken)
        {
            lock (_values)
            {
                _values.Remove(key);
            }

            return Task.CompletedTask;
        }
    }

    /// <summary>Persistent storage that delegates to an explicitly supplied secure adapter.</summary>
    internal sealed class SecureTokenStorage : IAuth4TokenStorage
    {
        private readonly ISecureStorageAdapter _adapter;

        public SecureTokenStorage(ISecureStorageAdapter adapter)
        {
            _adapter = adapter ?? throw new ArgumentNullException(nameof(adapter));
        }

        public bool IsPersistent => true;

        public Task<string> LoadAsync(string key, CancellationToken cancellationToken)
        {
            return _adapter.ReadAsync(key, cancellationToken);
        }

        public Task SaveAsync(string key, string value, CancellationToken cancellationToken)
        {
            return _adapter.WriteAsync(key, value, cancellationToken);
        }

        public Task DeleteAsync(string key, CancellationToken cancellationToken)
        {
            return _adapter.DeleteAsync(key, cancellationToken);
        }
    }
}
