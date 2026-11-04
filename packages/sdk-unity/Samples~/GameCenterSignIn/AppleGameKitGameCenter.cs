#if AUTH4_APPLE_GAMEKIT && (UNITY_IOS || UNITY_STANDALONE_OSX)
using System.Threading;
using System.Threading.Tasks;
using Apple.GameKit;
using UnityEngine;

namespace Auth4.Samples.GameCenterSignIn
{
    /// <summary>
    /// IAuth4GameCenter built on Apple's GameKit plug-in for Unity (com.apple.unityplugin.gamekit,
    /// https://github.com/apple/unityplugins). Add the plug-in, then add AUTH4_APPLE_GAMEKIT to the
    /// iOS and macOS scripting define symbols. The calls follow the plug-in's README; check them
    /// against the plug-in version you install.
    /// </summary>
    public sealed class AppleGameKitGameCenter : IAuth4GameCenter
    {
        /// <summary>Set for Apple Arcade games, which must send gamePlayerID instead of teamPlayerID.</summary>
        public bool IsAppleArcade { get; set; }

        private Task<GKLocalPlayer> _authenticated;

        public bool IsSupported => true;

        public async Task<GameCenterIdentity> FetchIdentityAsync(CancellationToken cancellationToken)
        {
            // GameKit shows its own sign-in UI the first time; later calls reuse the result.
            if (_authenticated == null || _authenticated.IsFaulted || _authenticated.IsCanceled)
            {
                _authenticated = GKLocalPlayer.Authenticate();
            }

            var local = await _authenticated;
            cancellationToken.ThrowIfCancellationRequested();
            var items = await local.FetchItems();
            return new GameCenterIdentity(
                IsAppleArcade ? local.GamePlayerId : local.TeamPlayerId,
                Application.identifier,
                items.PublicKeyUrl,
                items.GetSignature(),
                items.GetSalt(),
                items.Timestamp);
        }
    }
}
#endif
