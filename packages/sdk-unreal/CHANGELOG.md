# Changelog

## [Unreleased]

### Fixed

- `TryRestoreSession` (AUTH4D-354) reports success only after a refresh returned a usable access
  token. A transient failure keeps the stored credential, leaves `CurrentSession` empty and is
  retried by the next call; concurrent callers share one outcome; `invalid_grant` clears the
  credential and reports nothing stored; a sign-out during a pending restore wins.

- The guest upgrade accepts an `upgrade_uri` with a fragment, which now carries the browser
  verifier (AUTH4D-343), and puts the provider hint before it.

## [0.2.0] - 2026-10-10

### Fixed

- The `Auth4` module failed to link in modular (editor) builds because `Auth4Core` exported no
  symbols. `Auth4::Client` is now exported with `AUTH4CORE_API`.

### Added

- In-engine automation tests (`Auth4.*`), including sign-in, refresh and sign-out through
  `FHttpModule` against the mock server, and `Tests/run-engine-tests.mjs`, which builds the plugin
  with `BuildPlugin -StrictIncludes` and runs them. The release checks run it on Unreal Engine 5.7, so
  the plugin is no longer marked beta.

## [0.1.0] - 2026-10-06

### Added

- First preview of the auth4.dev plugin for Unreal Engine 5: device sign-in, guest sessions, guest
  upgrades through upgrade intents in the system browser (with an optional preferred provider),
  rotating refresh tokens and an `IAuth4SecureStorage` adapter interface.
- Blueprint nodes: **Sign In With Device**, **Sign In As Guest**, **Upgrade Guest**, **Get Access
  Token**, **Refresh Session**, **Restore Session** and **Sign Out**, plus the `UAuth4Subsystem`
  game instance subsystem.
- A protocol test suite that builds the core with CMake and runs it against a local mock server.
