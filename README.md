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

  * Regular Ethernet II frames are supported.
  * ARP packets (including gratuitous requests and replies) are supported.
  * 802.3 and 802.1Q are **not** supported.
  * Jumbo frames are **not** supported.

### IP layer

The only supported internetworking protocol is IPv4.

  * IPv4 header checksum is supported.
  * IPv4 fragmentation is **not** supported.
  * IPv4 options are **not** supported.
  * ICMPv4 header checksum is supported.
  * ICMPv4 echo requests and replies are supported.
  * ICMPv4 destination unreachable message is supported.
  * ICMPv4 parameter problem message is **not** supported.

### UDP layer

The UDP protocol is supported over IPv4.

  * UDP header checksum is supported.
  * UDP sockets are supported.

### TCP layer

The TCP protocol is supported over IPv4.

  * TCP header checksum is supported.
  * TCP options are **not** supported. In particular, the MSS of the remote endpoint
    is hardcoded at the default value, 536.
  * Reassembly of out-of-order segments is **not** supported.

Installation
------------

To use the _smoltcp_ library in your project, add the following to `Cargo.toml`:

```toml
[dependencies]
smoltcp = "0.1"
```

Usage example
-------------

_smoltcp_, being a freestanding networking stack, needs to be able to transmit and receive
raw frames. For testing purposes, we will use a regular OS, and run _smoltcp_ in
a userspace process. Only Linux is supported (right now).

On *nix OSes, transmiting and receiving raw frames normally requires superuser privileges, but
on Linux it is possible to create a _persistent tap interface_ that can be manipulated by
a specific user:

```sh
sudo ip tuntap add name tap0 mode tap user $USER
sudo ip link set tap0 up
sudo ip addr add 192.168.69.100/24 dev tap0
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

  * pings (`ping 192.168.69.1`),
  * UDP packets on port 6969 (`socat stdio udp4-connect:192.168.69.1:6969 <<<"abcdefg"`),
  * TCP packets on port 6969 (`socat stdio tcp4-connect:192.168.69.1:6969 <<<"abcdefg"`),

The buffers are only 64 bytes long, for convenience of testing resource exhaustion conditions.

License
-------

_smoltcp_ is distributed under the terms of both the MIT license
and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT)
for details.
