# auth4.dev for Unreal Engine

An Unreal Engine 5 plugin for auth4.dev. It mirrors the Unity SDK (`packages/sdk-unity`): device
sign-in, guest sessions, guest upgrades by email and social providers in the system browser, and
rotating refresh tokens kept in memory unless you supply a secure storage adapter.

The guide is at <https://auth4.dev/docs/unreal/>.

## Layout

| Path               | What it holds                                                                         |
| ------------------ | ------------------------------------------------------------------------------------- |
| `Auth4.uplugin`    | Plugin descriptor with two runtime modules.                                           |
| `Source/Auth4Core` | The protocol core in plain C++17: no engine headers and no exceptions.                |
| `Source/Auth4`     | The Unreal layer: settings, `UAuth4Subsystem`, Blueprint nodes and platform services. |
| `Tests`            | CMake build of the core, a local mock server and the protocol tests.                  |

## Install

Copy or link this directory to `<YourProject>/Plugins/Auth4`, regenerate project files and build.
Then set the tenant ID, native client ID and auth origin under **Project Settings > Plugins >
auth4.dev**. Create the native client in the console first.

## Tests

The core is tested outside the engine, so the suite needs CMake and a C++17 compiler but not
Unreal Engine:

```sh
node packages/sdk-unreal/Tests/run-tests.mjs
```

The runner builds `Tests/CMakeLists.txt` into `.generated/auth4d-153/cmake`, starts
`Tests/mock-server.mjs` on a free loopback port and runs every test. The mock server checks the
wire contract on each request: content types, tenant scoping, no tokens in URLs, and refresh
rotation with reuse detection. A JSON report goes to `.generated/auth4d-153/report.json`.

