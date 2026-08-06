# Vendored third-party libraries

Self-hosted because the webview CSP is `script-src 'self'` (no CDN). Served
from Vite's public assets at `/vendor/…` and loaded by `index.html`.

| File | Package | Version | License |
| ---- | ------- | ------- | ------- |
| `popper.min.js` | `@popperjs/core` | 2.11.8 | MIT |
| `tippy.umd.min.js` | `tippy.js` | 6.3.7 | MIT |
| `tippy.css` | `tippy.js` | 6.3.7 | MIT |

Popper must load before Tippy (Tippy consumes `window.Popper`). Note: the
`tippy-bundle.umd.*` file in the npm package is *not* self-contained in 6.3.7.
It still expects an external `window.Popper`, so we vendor Popper and the core
`tippy.umd.min.js` explicitly.

To re-vendor:

```sh
vendor_work="$(mktemp -d)"
npm install --prefix "$vendor_work" --no-save --package-lock=false \
  tippy.js@6.3.7 @popperjs/core@2.11.8

cp "$vendor_work/node_modules/@popperjs/core/dist/umd/popper.min.js" ui/public/vendor/popper.min.js
cp "$vendor_work/node_modules/tippy.js/dist/tippy.umd.min.js"        ui/public/vendor/tippy.umd.min.js
cp "$vendor_work/node_modules/tippy.js/dist/tippy.css"               ui/public/vendor/tippy.css
rm -rf "$vendor_work"
```

Using a temporary install prefix keeps these vendoring-only dependencies out of
the workspace manifest, lockfile, and `node_modules` tree.
