# Third-party source and pins

## dnstt

Source: https://www.bamsoftware.com/software/dnstt/dnstt-20260501.zip

Release: 2026-05-01. Downloaded from the author's HTTPS site on 2026-09-09.
Archive SHA-256:
`a7b21d3d787570d9127643e360e150d2da7b33aa8039d0546a04dcfe8ee1864f`.

The release is public domain, as stated in the retained
[COPYING](third_party/dnstt/COPYING). Its dependencies retain their own licenses.
`third_party/dnstt` contains the unmodified `dns`, `noise`, `turbotunnel`, and
`dnstt-server` directories, with the release's module files and notices. Unused
upstream CLI client/TLS-fingerprinting code is not copied.

`internal/dnsttclient/dns.go` and `dns_test.go` originate in the release's
`dnstt-client` directory. Adaptations: library package name, quiet errors,
4096-byte EDNS query envelope, legacy single-route pacing, explicit cancellation of both wire
loops, and nonblocking timer draining. `client.go` adapts the upstream KCP/Noise/
smux setup into a cancellable session with bounded buffers and deadlines.

## Conference pilot

Source: https://github.com/openlibrecommunity/olcrtc

Commit: `189d16c093c4f721376afb5eaa0213d132a11242`.
Module: `v0.0.2-0.20260905232354-189d16c093c4`.
Upstream project license: WTFPL. Source and transitive module checksums are pinned
by Go's module graph. Imported only by the `conference` build tag. No upstream
installation script is executed by our build.

## Other direct dependencies

- `github.com/coder/websocket`: ISC.
- `github.com/miekg/dns`: BSD-3-Clause.
- `github.com/xtaci/kcp-go/v5` and `github.com/xtaci/smux`: MIT.
- `github.com/flynn/noise` through dnstt: BSD-3-Clause.
- `golang.org/x/net`, `x/crypto` and other Go subrepositories: BSD-3-Clause.

Use `go list -m all` to inventory the exact transitive versions of a build and
retain the corresponding upstream license files when distributing artifacts.

## SimpleBLT DNS pool

Local adaptations retain the authenticated DNSTT wire protocol. The connection
pool follows KindlyVPN Android's `scripts/native/dnstt_pool.go`: staggered lanes,
least-loaded distribution, independent backoff, and one shared query budget.
Mobile buffers and the pool are bounded to eight lanes / 32 active streams.
Managed SSH creates one authenticated SSH client per independent DNS lane.
