# auth4.dev Authentication for Unity

`dev.auth4.sdk` signs players in to an auth4.dev tenant from native games:

- **Device login** (RFC 8628): show a short code, the player approves it on a phone or PC.
- **Guest sessions** with a stable user ID, upgraded later by email verification or an enabled
  social provider without losing the player's ID.
- **Account email**: `AddEmailAsync`, `ChangeEmailAsync` and `RemoveEmailAsync` let a signed-in
  player, for example one who signed in with Steam or Epic Games, manage a verified email address
  through the hosted pages.
- **Rotating refresh tokens** with single-flight refresh, so parallel game requests never replay a
  refresh token.

Native clients have no client secret. Access tokens are opaque: send them to your game server and
validate them there (see the server SDK). Tokens stay in memory unless you supply an
`ISecureStorageAdapter`; the package never uses `PlayerPrefs`.

Supported editors: verified on **Unity 6.3 LTS (6000.3)**. The package declares Unity 2022.3 as its
minimum; the runtime is compiled headlessly as .NET Standard 2.1 with C# 9 to keep that profile.

```csharp
var client = new Auth4Client(new Auth4ClientOptions
{
    TenantId = "ten_…",
    ClientId = "cli_…",                 // a native client allowing device_code and refresh_token
    AuthOrigin = "https://auth.auth4.dev",
    Transport = new UnityWebRequestTransport(),
});

var session = await client.SignInWithDeviceAsync(code =>
    ShowCode(code.UserCode, code.VerificationUri), cancellationToken: cts.Token);
var accessToken = await client.GetAccessTokenAsync();
```

See `Documentation~/README.md` for the full guide, and import the **Device Login** sample from the
Package Manager.
