## Developing AgentMFA

```sh
npm install        # Install the pinned Tauri and TypeScript toolchain
npm test           # Type-check, then test the core, CLI, desktop commands, UI helpers, and sidecar
npm run test:ui    # Run only the TypeScript UI helper tests
npm run lint       # Lint the workspace and the separate Tauri app crate
npm run typecheck  # Type-check the frontend without emitting files

npm start          # start Vite and launch the desktop app
npm run build      # build .app and .dmg bundles
```

### Testing against the sandbox

`npm test` is hermetic — it never reaches a network service. The broker's
end-to-end behaviour is covered separately, against the disposable Docker
stack in `dev/sandbox`:

```sh
npm run sandbox:up     # start the four upstreams (Docker required)
npm run sandbox:test   # drive real brokers against them
```

Each test file in `dev/sandbox/tests/` starts its own headless `mfa serve`
on a throwaway root and speaks the real wire planes — control socket,
manage plane, Postgres proxy, SSH agent socket, MCP host — against the
sandbox's HTTP, MCP, Postgres, and SSH services. It is not part of
`npm test` because it needs Docker; run it when changing the broker,
the data planes, or the approval path. See
[dev/sandbox/README.md](dev/sandbox/README.md) §5.

### Frontend-only mode

You can run the UI standalone in a browser, against a self-contained dev
mock (`ui/src/mock-bridge.ts`). The production bridge loads it only through a
compile-time development branch, so fixtures do not ship in the desktop
bundle. This is useful for rapidly iterating on the UI,
or if you're an AI agent, previewing design changes when it isn't possible
to build a Tauri application.

When running in frontend-only mode, there is no remote broker, and
every command is served from an in-memory fixture store, with seeded
secrets, connections, a wired-up agent, and past activity.

```sh
npm run frontend:dev   # vite dev server with hot reload
```

Then open:

- <http://127.0.0.1:1420/> — the main window
- <http://127.0.0.1:1420/#dropdown> — the compact menu-bar dropdown

### Frontend architecture

React owns the main-window and dropdown shells in `ui/app.tsx`. Transient UI
state and its schema live in `ui/src/app-state.ts`, backed by the small
external store in `ui/src/ui-store.ts`. Broker-owned secrets, connections,
identity, sessions, request queues, and settings live canonically in the
broker-scoped TanStack Query cache in `ui/src/query-client.ts`; query-backed
accessors on the shared state facade let the action layer migrate without
copying those responses into a second store. Activity remains in the UI store
because its stable paginated append flow needs an infinite-query migration,
not a single-response cache entry.

Feature views live under `ui/src/features/`. The shared direct-endpoint UI is
in `endpoint-view.tsx`, and onboarding/agent guides are in
`getting-started-view.tsx`. Feature modules may read the shared application
state and emit typed React actions, but they must not import the application
shell. This keeps the dependency direction `app.tsx → feature → state/core`.

Every form, sheet, and view is a controlled TSX component reading and writing
the store directly, so React reconciles in place and renders leave focus,
selection, and scroll untouched. Icons are declarative React SVG components;
first-party UI code has no HTML-string rendering boundary. A regression test
(`ui/tests/react-boundary.test.ts`) prevents raw HTML sinks from being added.

Pointer actions, context menus, and connection drag-and-drop use React's
synthetic event boundary. Browser-global keyboard, focus, scroll, and resize
events are installed by a React effect with symmetric cleanup; do not add
module-level document click listeners.

## The macOS Keychain

Secret values are one Keychain item each. macOS has two keychains behind the
same API and the choice decides whether reads are silent:

- The **data-protection keychain** grants access by code identity — a process
  may open a keychain access group only if its signature carries the matching
  `keychain-access-groups` entitlement. No per-item ACL, so no
  "…wants to use your confidential information…" dialog, ever, and no
  *Always Allow*.
- The **login keychain** grants access by per-item ACL, which is what puts
  that dialog up, once per item per signature.

`crates/aka-core/src/keychain/` probes at startup and uses the
data-protection keychain whenever the running binary can. The probe stores a
throwaway item and removes it: it has to be a *write*, because an unentitled
process is handed an empty data-protection keychain rather than being refused
by it, so every read comes back `errSecItemNotFound` whether or not the
entitlement is there. Only `SecItemAdd` has to name an access group, and only
it reports `errSecMissingEntitlement`.

Everything except the Security.framework binding in `keychain/darwin.rs` is
platform-independent and tested on Linux through the `KeychainApi` seam; the
fake in those tests reproduces the empty-not-refused behaviour, since a fake
that refused reads would let a read-based probe look correct.

What that means while developing:

- `npm start` / `tauri dev` and `cargo run` produce builds with no
  entitlement, so they use the login keychain and *do* prompt. That is the
  expected dev experience, not a bug.
- `npm run build` signs with the entitlement. `scripts/build.sh` generates
  `src-tauri/entitlements.signed.plist` from `src-tauri/entitlements.plist`
  plus `keychain-access-groups = <TEAMID>.com.aka.desktop`, reading the team
  ID from `APPLE_TEAM_ID` or off the signing identity's name. It refuses to
  build if it cannot resolve one; `AGENTMFA_NO_KEYCHAIN_ENTITLEMENT=1` opts
  out and accepts the prompts.
- `scripts/build.sh` loads signing settings from the ignored repository
  `.env` when it exists. Variables explicitly exported by the caller take
  precedence, so CI and one-off command-line overrides still work.
- Items written by earlier builds are in the login keychain. They migrate on
  first read: copied across, original deleted. Each one may prompt once more
  on the way, and never again.
- `mfa status` prints which keychain the store is on, and
  `<data-dir>/keychain.json` records it. A binary that cannot reach the
  data-protection keychain but finds a store recorded on it fails with an
  explanation rather than presenting an empty vault.
- `AKA_KEYCHAIN=login` forces the old behaviour — the escape hatch for
  running an unsigned `mfa` against a store the signed app owns.

### If a signed build will not launch

`keychain-access-groups` on its own, with no provisioning profile, is what
the default build signs with, and as far as we can establish that is enough
for Developer ID on macOS. The failure mode if it is not, is unambiguous:
macOS refuses to launch code carrying a restricted entitlement no profile
authorizes, so the app dies at startup rather than degrading. (The runtime
probe cannot help there — it never gets to run.)

The fix is a provisioning profile, and the build supports it:

```sh
APPLE_PROVISIONING_PROFILE=~/AgentMFA.provisionprofile npm run build
```

That adds `com.apple.application-identifier` — restricted for certain, which
is why it only appears on this path — and embeds the profile at
`Contents/embedded.provisionprofile`, which authorizes both entitlements.
Get the profile from the Apple developer portal: a **Developer ID** profile
for app id `com.aka.desktop` with the Keychain Sharing capability enabled.

Nothing about the app's behaviour changes between the two — same entitlement,
same access group, same runtime probe. The only question either answers is
whether macOS honours the entitlement at all, so try the default first.

Human presence is not independently enforced for vault reads. The signed app
reads its data-protection Keychain items without an OS dialog; submitting a
management action in the app or CLI is the authorization to perform it.
Agent traffic remains constrained by each connection's access policy, optional
Ask-before decision, pinned destination, and immediate revocation behavior.
Destructive UI actions such as rotating the shared key use ordinary in-app
confirmation dialogs.

The unsigned `mfa` binary uses the login keychain for an offline edit, so macOS
may still show a Keychain access dialog for those reads. That is a consequence
of the offline executable's Keychain access, not an AgentMFA presence policy;
online CLI commands go through the broker and do not touch the Keychain.

## Publishing

Prerequisites: one-time macOS cross-linker setup: `brew install zig`

1. Bump the workspace version in `Cargo.toml`; run
   `node scripts/npm/sync-versions.mjs`; commit.
2. Run `npm run npm:dist` on a host configured to cross-build every target.
3. Publish from the workspace root. The command verifies all five packages
   before publishing anything, then publishes the four platform packages
   first and the main package last, so no install can ever resolve a launcher
   whose binary package is missing:

   ```sh
   npm run npm:publish -- --dry-run
   ```

   ```sh
   npm run npm:publish
   ```

4. Publish the main application. For a distributable `.app`/`.dmg`,
   build with a Developer ID Application certificate.

   ```sh
   npm run build          # signed universal .app + .dmg (auto-detects identity)
   npm run build:release  # will also notarize, staple, and validate

   gh release create v0.1.0 \
     src-tauri/target/universal-apple-darwin/release/bundle/dmg/AgentMFA_0.1.0_universal.dmg \
     --target main \
     --title "AgentMFA 0.1.0" \
     --generate-notes
   ```
