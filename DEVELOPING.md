## Developing Multitool

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
   npm run build      # signed universal .app + .dmg (auto-detects the identity)
   npm run release    # will also notarize, staple, and validate
   ```
