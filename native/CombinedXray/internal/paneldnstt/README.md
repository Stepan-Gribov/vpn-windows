Operation-local adapter of David Fifield's DNSTT client wire protocol (CC0,
see COPYING), derived from the already-vendored native recovery client.

The panel adapter injects its own physical-interface-bound PacketConn, query
budget and cancellation context. It authenticates Noise, uses KCP+smux v2 and
returns streams to an operation-owned pool. No Xray/TURN singleton or recovery
source files are changed. Updates to Native/Recovery remain independently
verified by Scripts/verify_recovery_source.py.

The explicit Built-in DNS user VPN creates its own separate pool using this
wire adapter, with a 256 KiB receive buffer per lane. It never shares sessions,
listeners or cancellation with a panel operation.
