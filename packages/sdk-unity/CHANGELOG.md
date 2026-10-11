# Changelog

## [0.6.0] - 2026-10-07

### Added

- `Auth4Provider.Epic`: `UpgradeGuestAsync(Auth4Provider.Epic, …)` asks the hosted upgrade page to
  offer Epic Games first, for a "Save progress with Epic Games" button. As with Steam and Discord,
  the player still confirms on the page, and the page shows its usual choices if the application
  has Epic Games turned off.
- `LinkedIdentity.Provider` can be `epic`. Epic Games accounts carry no email address; use
  `AddEmailAsync` if the player wants to add one.

## [0.5.0] - 2026-10-06

### Added

- `AddEmailAsync` lets a signed-in player who has no email address, for example one who signed in
  with Steam, add one. It opens the hosted `/login/add-email` page with the `BrowserLauncher`,
  polls while the player verifies the address with an email code, and then replaces the session with
  a refreshed one for the same user and raises `SessionChanged`. It returns `AddEmailResult` with
  the session and the address.
- `Auth4AddEmailException` and `AddEmailFailure` (`GuestAccount`, `AlreadyAdded`,
  `EmailSignInDisabled`, `Expired`, `Denied` and `Cancelled`). An address that already belongs
  to another player is refused on the page, which lets the player try a different one.

## [0.4.0] - 2026-10-05

### Added

- `UpgradeGuestAsync(Auth4Provider provider, …)` asks the hosted upgrade page to offer Steam
  (`Auth4Provider.Steam`) or Discord (`Auth4Provider.Discord`) first, for a "Save progress with
  Steam" button. It works in the system browser on native platforms and in the WebGL popup. The
  player still confirms on the page and can choose another enabled method. If the application has
  the provider turned off, the page shows its usual choices.
- `LinkedIdentity.Provider` can be `steam`.
- The Device Login sample has a **Save progress with Steam** button.

## [0.3.0] - 2026-10-05

### Added

- `UpgradeGuestAsync` works in WebGL builds. With `Auth4ClientOptions.UpgradeWindow` set to
  `WebGLUpgradeWindow`, it opens the hosted `/login/upgrade` page in a popup and runs the browser
  window protocol through `Plugins/WebGL/Auth4Upgrade.jslib`: messages are accepted only from that
  popup on the exact auth origin, the guest token is posted only to the auth origin, and no token
  enters a URL or browser storage. Native platforms keep using the `BrowserLauncher`.
- `IAuth4UpgradeWindow`, `IAuth4UpgradeWindowHandle` and `Auth4UpgradeWindowMessage`, so the popup
  flow can be tested or replaced.
- `GuestUpgradeFailure` values `PopupBlocked`, `WindowClosed` and `SessionEnded` for the popup flow.
- When the browser no longer counts the input as a user gesture, the WebGL popup opens on the
  player's next pointer-up or touch-end. Start the upgrade from a pointer-down handler.
- The Device Login sample saves guest progress in WebGL builds too.

## [0.2.0] - 2026-10-05

### Added

- `UpgradeGuestAsync` upgrades a guest by email or Discord in the system browser on native
  platforms. It opens the hosted page through `IAuth4BrowserLauncher`, polls the upgrade intent at
  the server's interval (honouring `slow_down`), reports `GuestUpgradeProgress` and swaps the token
  set in one step, keeping the user ID.
- `UnityBrowserLauncher`, which calls `Application.OpenURL` and reports WebGL as unsupported.
- `Auth4GuestUpgradeException` with `Reason` `Conflict`, `Expired`, `Denied` or `Cancelled`.
- `Auth4ClientOptions.BrowserLauncher`.
- The Device Login sample saves guest progress with email or Discord (not shown in WebGL builds).

## [0.1.0] - 2026-10-04

### Added

- `Auth4Client` with injectable HTTP transport, clock and secure storage adapter.
- Device authorization with bounded polling, `slow_down` handling and cancellation.
- Guest sign-in, guest upgrade by email verification, single-flight refresh and revocation.
- `UnityWebRequestTransport` and the Device Login sample scene.
