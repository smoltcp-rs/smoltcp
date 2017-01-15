smoltcp
=======

_smoltcp_ is a standalone, event-driven TCP/IP stack that is designed for bare-metal,
real-time systems. Its design goals are simplicity and robustness. Its design anti-goals
include complicated compile-time computations, such as macro or type tricks, even
at cost of performance degradation.

_smoltcp_ does not need heap allocation *at all*, is [extensively documented][docs],
and compiles on stable Rust 1.15 and later.

[docs]: https://docs.rs/smoltcp/

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
  * Multiple packets will be transmitted without waiting for an acknowledgement.
  * Lost packets will be retransmitted with exponential backoff, starting at
    a fixed delay of 100 ms.
  * TCP urgent pointer is **not** supported; any urgent octets will be received alongside
    data octets.
  * Reassembly of out-of-order segments is **not** supported.
  * TCP options are **not** supported, in particular:
    * Maximum segment size is hardcoded at the default value, 536.
    * Window scaling is **not** supported, and the maximum buffer size is 65536.
  * Keepalive is **not** supported.

Installation
------------

To use the _smoltcp_ library in your project, add the following to `Cargo.toml`:

```toml
[dependencies]
smoltcp = "0.1"
```

The default configuration assumes a hosted environment, for ease of evaluation.
You probably want to disable default features and configure them one by one:

```toml
[dependencies]
smoltcp = { version = ..., default-features = false, features = [...] }
```

### Feature `use_std`

The `use_std` feature enables use of objects and slices owned by the networking stack through a
dependency on `std::boxed::Box` and `std::vec::Vec`. It also enables `smoltcp::phy::RawSocket`
and `smoltcp::phy::TapInterface`, if the platform supports it.

### Feature `use_alloc`

The `use_alloc` feature enables use of objects owned by the networking stack through a dependency
on `alloc::boxed::Box`. This only works on nightly rustc.

### Feature `use_collections`

The `use_collections` feature enables use of slices owned by the networking stack through a dependency
on `collections::vec::Vec`. This only works on nightly rustc.

### Feature `use_log`

The `use_log` feature enables logging of events within the networking stack through
the [log crate][log]. The events are emitted with the TRACE log level.

[log]: https://crates.io/crates/log

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

### examples/tcpdump.rs

_examples/tcpdump.rs_ is a tiny clone of the _tcpdump_ utility.

Unlike the rest of the examples, it uses raw sockets, and so it can be used on regular interfaces,
e.g. `eth0` or `wlan0`, as well as the `tap0` interface we've created above.

Read its [source code](/examples/tcpdump.rs), then run it as:

```sh
cargo build --example tcpdump
sudo ./target/debug/tcpdump eth0
```

### examples/server.rs

_examples/server.rs_ emulates a network host that can serve requests.

The host is assigned the hardware address `02-00-00-00-00-01` and IPv4 address `192.168.69.1`.

Read its [source code](/examples/server.rs), then run it as:

```sh
cargo run --example server -- tap0
```

It responds to:

  * pings (`ping 192.168.69.1`);
  * UDP packets on port 6969 (`socat stdio udp4-connect:192.168.69.1:6969 <<<"abcdefg"`),
    where it will respond "yo dawg" to any incoming packet;
  * TCP packets on port 6969 (`socat stdio tcp4-connect:192.168.69.1:6969`),
    where it will respond "yo dawg" to any incoming connection and immediately close it;
  * TCP packets on port 6970 (`socat stdio tcp4-connect:192.168.69.1:6970 <<<"abcdefg"`),
    where it will respond with reversed chunks of the input indefinitely.

The buffers are only 64 bytes long, for convenience of testing resource exhaustion conditions.

Fault injection is available through the `--drop-chance` and `--corrupt-chance` options,
with values in percents. A good starting value is 15%.

License
-------

_smoltcp_ is distributed under the terms of 0-clause BSD license.

See [LICENSE-0BSD](LICENSE-0BSD.txt) for details.
