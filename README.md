smoltcp
=======

_smoltcp_ is a standalone, event-driven TCP/IP stack that is designed for bare-metal,
real-time systems. Its design goals are simplicity and robustness. Its design anti-goals
include complicated compile-time computations, such as macro or type tricks, even
at cost of performance degradation.

Features
--------

_smoltcp_ is missing many widely deployed features, whether by design or simply because
no one implemented them yet. To set expectations right, both implemented and omitted
features are listed.

### Media layer

The only supported medium is Ethernet.

  * Regular 802.3 frames are supported.
  * 802.1Q is not supported.
  * Jumbo frames are not supported.
  * CRC calculation is not supported.
  * ARP packets are supported.
  * ARP probes or announcements are not supported.

### IP layer

IP is not supported yet.

### UDP layer

UDP is not supported yet.

### TCP layer

TCP is not supported yet.

Installation
------------

To use the _smoltcp_ library in your project, add the following to `Cargo.toml`:

```toml
[dependencies]
smoltcp = "0.1"
```

Usage example
-------------

_smoltcp_, being a userspace networking stack, needs to be able to send and receive raw frames.
This normally requires superuser privileges, but on Linux it is possible to create
a _persistent tap interface_ that can be manipulated by a specific user:

```sh
sudo ip tuntap add name tap0 mode tap user $USER
sudo ip link set tap0 up
sudo ip addr add 192.168.69.100 dev tap0
```

### smoltcpdump

_smoltcpdump_ is a tiny clone of the _tcpdump_ utility.

Unlike the rest of the examples, it uses raw sockets, and so it can be used on regular interfaces,
e.g. `eth0` or `wlan0`, as well as the `tap0` interface we've created above.

Read its [source code](/examples/smoltcpdump.rs), then run it as:

```sh
cargo build --example smoltcpdump
sudo ./target/debug/smoltcpdump eth0
```

### smoltcpserver

_smoltcpserver_ emulates a network host that can serve requests.

The host is assigned the hardware address `02-00-00-00-00-01` and IPv4 address `192.168.69.1`.

Read its [source code](/examples/smoltcpserver.rs), then run it as:

```sh
cargo run --example smoltcpserver -- tap0
```

It responds to:

  * pings (`ping 192.168.69.1`) (actually not yet).

License
-------

_smoltcp_ is distributed under the terms of both the MIT license
and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT)
for details.
