# auth4.dev SDKs

The client and server SDKs for [auth4.dev](https://auth4.dev), authentication for games and web
apps.

| SDK     | Package                                        | Registry        | Directory              | Documentation                                             |
| ------- | ---------------------------------------------- | --------------- | ---------------------- | --------------------------------------------------------- |
| Browser | `@auth4/sdk-browser`                           | npm             | `packages/sdk-browser` | [auth4.dev/docs/browser](https://auth4.dev/docs/browser/) |
| Server  | `@auth4/sdk-server`                            | npm             | `packages/sdk-server`  | [auth4.dev/docs/server](https://auth4.dev/docs/server/)   |
| Next.js | `@auth4/nextjs`                                | npm             | `packages/sdk-nextjs`  | [auth4.dev/docs/nextjs](https://auth4.dev/docs/nextjs/)   |
| Unity   | `dev.auth4.sdk` (UPM)                          | OpenUPM         | `packages/sdk-unity`   | [auth4.dev/docs/unity](https://auth4.dev/docs/unity/)     |
| Unreal  | `Auth4` plugin                                 | Not yet         | `packages/sdk-unreal`  | [auth4.dev/docs/unreal](https://auth4.dev/docs/unreal/)   |
| Godot   | `addons/auth4`                                 | Not yet         | `packages/sdk-godot`   | [auth4.dev/docs/godot](https://auth4.dev/docs/godot/)     |
| .NET    | `Auth4.Server`, `Auth4.Server.AspNetCore`      | Not yet (NuGet) | `packages/sdk-dotnet`  | [auth4.dev/docs/dotnet](https://auth4.dev/docs/dotnet/)   |
| Go      | `github.com/Plorax/auth4-sdks/packages/sdk-go` | Not yet tagged  | `packages/sdk-go`      | [auth4.dev/docs/go](https://auth4.dev/docs/go/)           |
| Python  | `auth4`                                        | Not yet (PyPI)  | `packages/sdk-python`  | [auth4.dev/docs/python](https://auth4.dev/docs/python/)   |

The Unreal, Godot, .NET, Go and Python SDKs are not published to a registry yet. Use them from a
copy of this repository: see each directory's README. `node scripts/sdk/check.mjs` only checks
their licence and version metadata; their own test suites need the engine or language toolchain
(Unreal or CMake, Godot, .NET 8, Go, Python 3.10+).

## This repository is a read-only mirror

The SDKs are developed in a private repository together with the auth4.dev service. Every change
that passes its checks is copied here as a single commit whose message ends with
`Source: Plorax/auth4.dev@<commit>`. Nothing is committed to this repository directly, so pull
requests cannot be merged here.

- **Bugs and questions**: open an issue in this repository.
- **Changes**: you are welcome to open a pull request to show a fix. A maintainer ports it to the
  source repository, crediting you, and it arrives here with the next sync. The pull request is then
  closed.

## Releases

Releases are tags created by the mirror: `sdk-browser/v<version>`, `sdk-server/v<version>`,
`sdk-nextjs/v<version>` and `dev.auth4.sdk/v<version>`. The npm packages are published from this
repository by `.github/workflows/publish-sdks.yml` with
[npm provenance](https://docs.npmjs.com/generating-provenance-statements), so each published
version links back to the tagged commit and workflow run here. OpenUPM builds the Unity package from
its tag.

## Building and checking locally

Node 26 and pnpm 10 (the versions in `package.json`):

```sh
pnpm install --frozen-lockfile
pnpm typecheck
pnpm test
node scripts/sdk/check.mjs          # builds, packs and checks every SDK as it would be published
```

The other SDKs build with their own tools, for example `go vet ./...` and `go test ./...` in
`packages/sdk-go`, `dotnet test packages/sdk-dotnet/tests/Auth4.Server.Tests` and `pytest` in
`packages/sdk-python`.

`packages/contracts` holds the wire shapes the server SDK shares with the service. It is not
published on its own; the build inlines it into `@auth4/sdk-server`.

## Licence

MIT, see [LICENSE](LICENSE).
