using System;
using System.Threading;
using System.Threading.Tasks;

namespace Auth4
{
    /// <summary>
    /// Platform adapter for Apple Game Center (AUTH4D-311). It authenticates the local player with
    /// GameKit and returns the identity-verification data of
    /// GKLocalPlayer.fetchItems(forIdentityVerificationSignature:). The client never calls GameKit
    /// itself, so the runtime stays engine- and plugin-independent; the GameCenterSignIn sample has an
    /// adapter built on Apple's GameKit Unity plug-in.
    /// </summary>
    public interface IAuth4GameCenter
    {
        /// <summary>False where Game Center is unavailable, for example on Windows or Android.</summary>
        bool IsSupported { get; }

        /// <summary>
        /// Authenticates the local Game Center player if needed and fetches a fresh identity
        /// verification signature. Call it right before signing in: the server accepts a signature
        /// for five minutes, and only once.
        /// </summary>
        Task<GameCenterIdentity> FetchIdentityAsync(CancellationToken cancellationToken);
    }

    /// <summary>
    /// What GameKit signed for the local player. The server checks the signature against Apple's
    /// public key; nothing here is trusted on its own.
    /// </summary>
    public sealed class GameCenterIdentity
    {
        /// <param name="playerId">GKPlayer.teamPlayerID, or gamePlayerID for Apple Arcade games.</param>
        /// <param name="bundleId">The app's bundle identifier (CFBundleIdentifier).</param>
        /// <param name="publicKeyUrl">The publicKeyURL GameKit returned.</param>
        /// <param name="signature">The signature data GameKit returned.</param>
        /// <param name="salt">The salt data GameKit returned.</param>
        /// <param name="timestamp">GameKit's timestamp, milliseconds since the Unix epoch.</param>
        public GameCenterIdentity(
            string playerId,
            string bundleId,
            string publicKeyUrl,
            byte[] signature,
            byte[] salt,
            ulong timestamp)
        {
            if (string.IsNullOrEmpty(playerId) || string.IsNullOrEmpty(bundleId) ||
                string.IsNullOrEmpty(publicKeyUrl))
            {
                throw new ArgumentException("The Game Center player, bundle and key URL are required.");
            }

            if (signature == null || signature.Length == 0 || salt == null || salt.Length == 0 || timestamp == 0)
            {
                throw new ArgumentException("The Game Center signature, salt and timestamp are required.");
            }

            PlayerId = playerId;
            BundleId = bundleId;
            PublicKeyUrl = publicKeyUrl;
            Signature = (byte[])signature.Clone();
            Salt = (byte[])salt.Clone();
            Timestamp = timestamp;
        }

        public string PlayerId { get; }

        public string BundleId { get; }

        public string PublicKeyUrl { get; }

        public byte[] Signature { get; }

        public byte[] Salt { get; }

        public ulong Timestamp { get; }
    }
}
