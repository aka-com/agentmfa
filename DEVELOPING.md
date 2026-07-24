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

### Frontend-only mode

You can run the UI standalone in a browser, against a self-contained dev
mock (`ui/src/bridge.ts`). This is useful for rapidly iterating on the UI,
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
state lives in the small external store in `ui/src/ui-store.ts`; broker-owned
reads go through the broker-scoped TanStack Query client in
`ui/src/query-client.ts`.

Every form is a controlled TSX component reading and writing the store
directly, so React reconciles in place and renders leave focus, selection,
and scroll untouched. The remaining read-mostly view and sheet helpers still
emit HTML strings that cross one compatibility boundary (`SafeMarkup`), where
they are sanitized with DOMPurify and parsed into React elements. New UI
should be written as TSX components rather than adding new HTML-string
templates; a regression test (`ui/tests/react-boundary.test.ts`) guards the
boundary.

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

`crates/aka-core/src/keychain/` probes at startup — a lookup of an item that
cannot exist, where `errSecItemNotFound` means "allowed" and
`errSecMissingEntitlement` means "not" — and uses the data-protection keychain
whenever the running binary can. Everything except the Security.framework
binding in `keychain/darwin.rs` is platform-independent and tested on Linux
through the `KeychainApi` seam.

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
- Items written by earlier builds are in the login keychain. They migrate on
  first read: copied across, original deleted. Each one may prompt once more
  on the way, and never again.
- `mfa status` prints which keychain the store is on, and
  `<data-dir>/keychain.json` records it. A binary that cannot reach the
  data-protection keychain but finds a store recorded on it fails with an
  explanation rather than presenting an empty vault.
- `AKA_KEYCHAIN=login` forces the old behaviour — the escape hatch for
  running an unsigned `aka` against a store the signed app owns.

Human presence is *not* enforced by the Keychain. It is enforced by the
shell's own LocalAuthentication gate (`src-tauri/src/auth.rs`) and the
presence window in `Store` — one prompt, then a sliding window
(`presence_window_secs`, 15 minutes by default, 12-hour hard ceiling).
Attaching `SecAccessControl(userPresence)` to the items instead would move
that decision into the OS, but Touch ID reuse there caps at five minutes, so
it would prompt more often than the app does today rather than less.

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
   ```
