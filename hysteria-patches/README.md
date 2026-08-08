# RiseVPN Hysteria patch series

The files in this directory are the complete RiseVPN delta on top of upstream
Hysteria. Upstream source is intentionally not vendored.

Pinned upstream tag: `app/v2.9.2`.

Apply and test:

```sh
./scripts/build-hysteria.sh
```

The patch series keeps the Hysteria wire protocol and cryptography unchanged. It adds
an optional `PolicyAuthenticator`, parses policy fields returned by HTTP auth,
enforces per-session TCP/UDP bandwidth, asks the loopback agent to authorize
destinations, performs conservative P2P checks, and prioritizes authenticated
Plus/Ultra sessions when the node is saturated. Legacy auth backends keep
upstream behavior.

When updating upstream, change `UPSTREAM_VERSION`, run
`scripts/check-hysteria-update.sh <new-tag>`, resolve only reported patch
conflicts, and regenerate the patch with `git format-patch`. Never edit the
protocol or cryptographic packages for a RiseVPN policy change.
