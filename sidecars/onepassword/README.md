# Multitool 1Password SDK sidecar

This helper is the process boundary between the Rust broker and the official
1Password Go SDK. One long-lived helper is started per desktop-app or service-
account integration. It accepts framed JSON only on inherited standard-I/O
pipes and deliberately has no command-line flags that could expose tokens or
secret references in the process list.

Build it next to the Multitool binary:

```sh
go build -trimpath -o ../../target/debug/multitool-onepassword .
```

For development, `MULTITOOL_ONEPASSWORD_SIDECAR` may point to an absolute
helper path. Packaged builds should place `multitool-onepassword` beside the
broker executable and codesign both artifacts.
