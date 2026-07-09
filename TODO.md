# TODO

## Document adopter-facing security model and limitations

Add a consolidated **Security model and limitations** section to `README.md`
covering the following product-level facts:

- [ ] Explain that HTTP connections pin an origin, not an allowed set of paths
  or operations. Full access and standing rules allow any accepted method and
  path on that origin; read access allows GET/HEAD on any path.
- [ ] Explain that Postgres statements, WebSocket frames, and SSH operations
  are not individually inspected or approved, and that a multi-connect ticket
  may establish several sessions under one decision.
- [ ] Describe the v1 standing-rule scope: an agent name plus an entire stable
  connection, with no path, method, query, read-only, expiry, or deny-rule
  constraints. Distinguish it from a token-generation- and
  connection-revision-bound, scoped 15-minute access session.
- [ ] State that agent names are self-asserted and that pairing under an
  existing name inherits that name's standing rules.
- [ ] Qualify identity pinning: interpreted runtimes may share a `node` or
  `python` identity, separate processes may share a signing identity,
  unsigned/ad-hoc fingerprints are weaker, and an in-process compromise
  already runs as the accepted peer.
- [ ] State that a paired agent can list every configured connection target,
  including internal hostnames and database users, but not secret names, IDs,
  or injection templates.
- [ ] Describe response-redaction limits: exact rendered credentials are
  removed and common encodings are handled best-effort, but arbitrary upstream
  transformations cannot be recognized reliably.
- [ ] Describe clipboard exposure: explicit copy puts the full value on the
  general macOS pasteboard; concealed marking and the conditional 30-second
  clear reduce but do not eliminate access by local apps or clipboard tools.
- [ ] Describe residual webview-compromise capabilities, including metadata
  access, approval of read-classified requests, capture of newly entered
  values, connection renames, pairing revocation, and session termination.
- [ ] Consolidate the existing activity-log warning: persistence is best
  effort and the local history is neither complete nor tamper-evident.
