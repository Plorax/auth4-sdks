# auth4.dev Unity SDK guide

## Install

Add the package from disk or Git in the Package Manager, or reference it in `Packages/manifest.json`:

```json
{ "dependencies": { "dev.auth4.sdk": "file:../path/to/packages/sdk-unity" } }
```

Create a **native** client in the auth4.dev console that allows the `device_code` and
`refresh_token` grants. Native clients never have a client secret, and the SDK cannot send one.
WebGL builds run in a web page, so they use a **browser** client whose allowed origins include the
page that hosts the build (see "In a WebGL build").

## Assemblies

| Assembly                    | Contents                                                                                         |
| --------------------------- | ------------------------------------------------------------------------------------------------ |
| `Auth4.Runtime`             | Engine-independent client (`noEngineReferences`).                                                |
| `Auth4.Unity`               | `UnityWebRequestTransport`, `UnityBrowserLauncher`, `WebGLUpgradeWindow` and its WebGL `.jslib`. |
| `Auth4.Samples.DeviceLogin` | The importable sample (`Samples~/DeviceLogin`).                                                  |

## Client

```csharp
var client = new Auth4Client(new Auth4ClientOptions
{
    TenantId = "ten_…",
    ClientId = "cli_…",
    AuthOrigin = "https://auth.auth4.dev",    // http is accepted only for loopback hosts
    Transport = new UnityWebRequestTransport(), // default: HttpClientTransport
    SecureStorage = null,                       // in-memory only; see "Token storage"
    BrowserLauncher = new UnityBrowserLauncher(), // UpgradeGuestAsync on native platforms
    UpgradeWindow = new WebGLUpgradeWindow(),     // UpgradeGuestAsync in WebGL builds
});
```

Every dependency is injectable: `IAuth4HttpTransport`, `IAuth4Clock`, `ISecureStorageAdapter`,
`IAuth4BrowserLauncher` and `IAuth4UpgradeWindow`.
Await the client from the main thread; it never uses `ConfigureAwait(false)`, so continuations
return to Unity's synchronization context.

## Device login

```csharp
var authorization = await client.StartDeviceAuthorizationAsync(); // "openid offline_access"
ShowCode(authorization.UserCode, authorization.VerificationUri, authorization.VerificationUriComplete);
try
{
    var session = await client.PollDeviceAuthorizationAsync(authorization, cts.Token);
}
catch (Auth4DeviceAuthorizationException error) when (error.Reason == DeviceAuthorizationFailure.Denied) { … }
catch (Auth4DeviceAuthorizationException error) when (error.Reason == DeviceAuthorizationFailure.Expired) { … }
catch (OperationCanceledException) { /* the player cancelled; polling can be resumed until expiry */ }
```

Polling waits the server interval (minimum five seconds) before each request, adds five seconds on
every `slow_down`, backs off on network and 5xx errors (`MaxConsecutiveTransientPollFailures`), and
stops at the code's expiry or after `MaxDevicePollAttempts`. Verification URLs from another origin
are rejected. A refresh token is issued only when `offline_access` is requested and approved.

## Guest sessions and upgrades

### In the system browser (email or a social provider)

On native platforms, `UpgradeGuestAsync` links an email address or a Discord, Steam or other
social account the project has turned on (such as Epic Games) through the hosted page in the player's browser, using an upgrade intent (AUTH4D-67):

```csharp
var guest = await client.SignInAsGuestAsync();
try
{
    var result = await client.UpgradeGuestAsync(
        progress => ShowStatus(progress.Stage, progress.UpgradeUri), // e.g. offer "Open again"
        cts.Token);
    // result.Session.UserId == guest.UserId; result.Identity.Provider is "email", "discord" or "steam".
}
catch (Auth4GuestUpgradeException error) when (error.Reason == GuestUpgradeFailure.Conflict) { … }
catch (Auth4GuestUpgradeException error) when (error.Reason == GuestUpgradeFailure.Denied) { … }
catch (Auth4GuestUpgradeException error) when (error.Reason == GuestUpgradeFailure.Expired) { … }
catch (Auth4GuestUpgradeException error) when (error.Reason == GuestUpgradeFailure.Cancelled) { … }
```

For a button such as **Save progress with Steam**, pass the provider first:
`UpgradeGuestAsync(Auth4Provider.Steam, onProgress, cts.Token)`. The same hint works with
`Auth4Provider.Discord`, `Auth4Provider.Epic`, `Auth4Provider.Google`, `Auth4Provider.Apple` and
`Auth4Provider.Microsoft` (AUTH4D-213). This
works on native platforms and in WebGL builds. The page then shows that provider as the first, main
choice. The player still confirms on the page and can pick another enabled method. If the
application has the provider turned off, the page shows its usual choices.

1. The SDK creates an intent with the guest access token and receives a public handle, a poll
   secret (kept in memory, never logged or stored) and the page URL.
2. It opens the page with `BrowserLauncher.Open` (`UnityBrowserLauncher` calls
   `Application.OpenURL`). The player links an account and confirms there.
3. It polls `POST /t/{tenantId}/guest/upgrade-intent/token` after each server interval (at least
   five seconds). `slow_down` moves to the interval the server returns, or adds five seconds;
   network and 5xx errors back off as in device login. Polling stops at the intent's expiry (ten
   minutes) or after `MaxDevicePollAttempts`.
4. On success the access, refresh and ID tokens are replaced in one step under the client's lock:
   secure storage is written first, then memory, then `SessionChanged` fires once with the upgraded,
   non-guest session. The user ID does not change.

Progress is reported as `OpeningBrowser`, `WaitingForPlayer` (before each poll) and `Completed`.
Exceptions thrown by the callback are ignored.

`Auth4GuestUpgradeException.Reason`:

| Reason      | Meaning                                                                      |
| ----------- | ---------------------------------------------------------------------------- |
| `Conflict`  | `identity_in_use`: the account belongs to another player. The guest is kept. |
| `Denied`    | The player chose **Not now**. The guest is kept.                             |
| `Expired`   | The intent expired before the player finished. Start a new upgrade.          |
| `Cancelled` | Your token fired. `InnerException` is the `OperationCanceledException`.      |

- `UpgradeGuestAsync` uses the `UpgradeWindow` where its `IsSupported` is true (WebGL builds) and
  the `BrowserLauncher` otherwise. With neither supported (`UnityBrowserLauncher` reports WebGL as
  unsupported), it throws `PlatformNotSupportedException` before contacting the API.
- Only one upgrade runs at a time per client. A poll that has been sent is not cancelled, because
  the token set is released exactly once.
- If the player finishes in the browser after you cancel, the account is still upgraded but the
  guest session is revoked; the player signs in with the linked email, Discord or Steam account.
- If the game refreshes the guest after the page finished, the refresh fails with
  `Auth4SessionExpiredException` (the guest session was revoked); a later successful poll still
  installs the upgraded session. Calling `SignOutAsync` during the upgrade wins: the new tokens are
  revoked and `InvalidOperationException` is thrown.

### In a WebGL build (popup window)

A WebGL game already runs in a browser, so `UpgradeGuestAsync` opens the hosted
`/login/upgrade?tenant_id=…&client_id=…` page (plus `&provider=…` when you pass one) in a popup and runs the same window protocol as the
browser SDK's `upgradeGuest()` (`docs/api-spec/auth4d-23.md`), through
`Runtime/Unity/Plugins/WebGL/Auth4Upgrade.jslib`. Set `UpgradeWindow = new WebGLUpgradeWindow()`;
on other platforms it reports `IsSupported = false` and the system-browser flow is used.

- Use a **browser** client. Its allowed origins must include the origin that serves the WebGL
  build: the hosted page posts only to registered origins, and guest sign-in from the page is
  accepted from them too (AUTH4D-122).
- The bridge accepts a message only when `event.origin` is exactly the auth origin and
  `event.source` is the popup it opened. It answers each `ready` (whose tenant and client must
  match) by posting a fresh guest access token to that window with the auth origin as the target
  origin. The URL carries no token, nothing is written to browser storage, and the result handed
  to C# is zeroed in the wasm heap as soon as C# has copied it.
- On `complete` the token set is checked and replaced exactly as in the system-browser flow: the user
  ID must not change, `SessionChanged` fires once, and the guest is otherwise kept.
- Progress is `OpeningBrowser`, `WaitingForPlayer` (the popup opened) and `Completed`.
  `UpgradeUri` is the popup URL, `ExpiresAt` is `DateTimeOffset.MaxValue` and `IntervalSeconds` is 0:
  there is no intent and no polling.
- Extra `Reason` values: `PopupBlocked` (the browser refused the popup), `WindowClosed` (the
  player closed it) and `SessionEnded` (the guest signed out, or the server ended the guest session;
  no token is sent after that). **Not now** is `Denied`; cancelling your token closes the popup.
- After `Conflict` the popup lets the player link a different credential. The client keeps
  answering it, so a later success still replaces the token set and raises `SessionChanged`. A new
  `UpgradeGuestAsync` call stops the old listener and reuses the same popup.

#### Open the popup from a pointer-down handler

Browsers open popups only inside an input event, but Unity WebGL handles input a frame after the
browser's event has returned. Start the upgrade when the button is **pressed**, not when it is
clicked, so the popup can open on the release:

```csharp
public sealed class SaveProgressButton : MonoBehaviour, IPointerDownHandler
{
    public void OnPointerDown(PointerEventData eventData) => SaveProgress();

    private async void SaveProgress()
    {
        try
        {
            var result = await Game.Auth.UpgradeGuestAsync(); // opens before the first await
        }
        catch (Auth4GuestUpgradeException error) when (error.Reason == GuestUpgradeFailure.PopupBlocked) { … }
    }
}
```

`UpgradeGuestAsync` calls the bridge before its first `await`. Where the browser still counts the
press as a user gesture (`navigator.userActivation.isActive`, as in current Chrome, Edge, Firefox
and Safari), the popup opens at once. Otherwise the bridge waits and opens it in the next real
`pointerup` or `touchend` on the page, which is the release of that same press. A uGUI
`Button.onClick` fires after the release, so in a browser without an active gesture the player
would have to click a second time; prefer `IPointerDownHandler`. If the browser still blocks the
window, `UpgradeGuestAsync` throws with `PopupBlocked`.

### In the game (email only)

```csharp
var guest = await client.SignInAsGuestAsync();      // guest.UserId is stable
var flow = await client.BeginGuestUpgradeAsync();   // linking intent, valid ~5 minutes
await client.StartEmailVerificationAsync(flow, email);
var proofId = await client.ConfirmEmailVerificationAsync(flow, email, code);
var result = await client.CompleteGuestUpgradeAsync(flow, proofId);
// result.Session.UserId == guest.UserId; the session and refresh token are replaced.
```

- Sign-in methods refuse to replace an active session, so a guest is never abandoned silently.
  Upgrade it or call `SignOutAsync` first.
- `409 identity_in_use` means the email already belongs to another account. The guest session is
  unchanged; ask the player to sign in to that account explicitly. Accounts are never merged.
- If the server returns a different user ID, the SDK revokes the returned credentials, clears the
  local session and throws `invalid_response`.
- The linking flow cookie is held in memory by the client and sent only to the auth origin. The
  hosted-login email endpoints require the auth origin as `Origin`, which the SDK sets.
- Use `UpgradeGuestAsync` for Discord, Steam, Epic Games, Google, Apple and Microsoft. WebGL builds can't use these in-game steps,
  because the browser controls `Cookie`, `Origin` and `Set-Cookie`; they use the popup window
  instead.

## Adding an email address

A player who signed in with Steam (or Discord) has no email address. `AddEmailAsync` lets them add
one to the same account. It opens the hosted `/login/add-email` page with the `BrowserLauncher`,
the player verifies the address with an email code, and the game polls until it gets a refreshed
session for the same user:

```csharp
try
{
    var result = await client.AddEmailAsync(cancellationToken: cts.Token);
    Debug.Log("Added " + result.Email);
}
catch (Auth4AddEmailException error)
{
    // GuestAccount, AlreadyAdded, EmailSignInDisabled, Expired, Denied or Cancelled.
    Debug.Log("No email address was added: " + error.Reason);
}
```

An address that already belongs to another player is refused on the page without saying why, and
the player can try a different one. Guests use `UpgradeGuestAsync` instead. The page URL holds
only a public handle; the poll secret and tokens stay in the game.

## Changing or removing an email address

`ChangeEmailAsync` and `RemoveEmailAsync` work the same way. They open the hosted
`/login/change-email` or `/login/remove-email` page, poll, and then replace the session with a
refreshed one for the same user and raise `SessionChanged`:

```csharp
try
{
    var changed = await client.ChangeEmailAsync(cancellationToken: cts.Token);
    Debug.Log("You now sign in with " + changed.Email);
}
catch (Auth4AddEmailException error)
{
    // GuestAccount, NotAdded, EmailSignInDisabled, Expired, Denied or Cancelled.
    Debug.Log("The email address was not changed: " + error.Reason);
}

try
{
    await client.RemoveEmailAsync(cancellationToken: cts.Token);
}
catch (Auth4AddEmailException error) when (error.Reason == AddEmailFailure.OnlySignInMethod)
{
    // The address is the player's only way to sign in; link another account first.
}
```

A change sends a code to the new address, and `ChangeEmailResult` holds the new address and email
identity. A removal needs only the player's confirmation and returns `RemoveEmailResult` with the
session. Each method opens only its own hosted page on the auth origin. Only one guest upgrade or
email request runs at a time; a second call throws `InvalidOperationException`.

## Tokens

`GetAccessTokenAsync()` returns the in-memory access token, refreshing 30 seconds before expiry
(`AccessTokenRefreshMargin`). Concurrent callers share a single refresh request, and the rotated
refresh token replaces the old one before any caller continues, so ordinary parallel requests do
not trigger refresh-token replay detection. Cancelling a waiter does not cancel the shared request.

`invalid_grant` raises `Auth4SessionExpiredException`, clears the session and storage and raises
`SessionChanged(null)`. Network and 5xx failures keep the session (`Auth4Exception.IsTransient`).

`SignOutAsync()` revokes the refresh token (or the access token when none exists) and always clears
local state; it returns `false` if the server could not confirm revocation.

## Token storage

Without `SecureStorage`, refresh tokens live only in memory and the player signs in again after a
restart. To persist sessions, implement `ISecureStorageAdapter` on top of the platform's protected
store, such as the iOS Keychain, Android Keystore-backed encryption, Windows DPAPI or a console
vendor's protected save API, and pass it explicitly. Then call `TryRestoreSessionAsync()` at start-up.

Adapters must encrypt with an OS-protected key and must never write to `PlayerPrefs`, plain files or
logs. Only the refresh token, user ID and guest flag are stored; access tokens are never persisted.

## Verification

Headless protocol tests (requires the .NET SDK):

```sh
dotnet test packages/sdk-unity/Tests~/Auth4.Protocol.Tests/Auth4.Protocol.Tests.csproj
```

They also compile `Runtime/` (without `Runtime/Unity`) as .NET Standard 2.1 with C# 9 and warnings as
errors.

WebGL bridge (Playwright): a minimal harness page loads the real `.jslib` through a small
Emscripten shim (`Tests~/WebGL`) and runs it against the built hosted upgrade page:

```sh
pnpm exec playwright test -c tests/e2e/auth4d-69.playwright.config.ts
```

Package structure:

```sh
node packages/sdk-unity/Tests~/validate-package.mjs
```

Unity import and compile check (Unity 6.3 LTS, 6000.3.x):

```powershell
./examples/unity/verify-unity.ps1 -UnityPath "C:\Program Files\Unity\Hub\Editor\6000.3.1f1\Editor\Unity.exe"
```

The script copies `Samples~/DeviceLogin` into `examples/unity/Assets/Samples` as the Package Manager
does, compiles `Auth4.Runtime`, `Auth4.Unity` and the sample in batch mode, opens the sample scene
and checks that it contains the sample component. It fails on any `error CS` line. On macOS or
Linux, run the same Unity command line:
`Unity -batchmode -nographics -projectPath examples/unity -executeMethod Auth4SampleVerifier.Verify -logFile -`
after copying the sample folder.
