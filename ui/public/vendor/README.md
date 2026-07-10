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
npm install --no-save tippy.js@6 @popperjs/core@2
cp node_modules/@popperjs/core/dist/umd/popper.min.js ui/public/vendor/popper.min.js
cp node_modules/tippy.js/dist/tippy.umd.min.js        ui/public/vendor/tippy.umd.min.js
cp node_modules/tippy.js/dist/tippy.css               ui/public/vendor/tippy.css
```
