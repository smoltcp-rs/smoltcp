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
  * Unicast and broadcast packets are supported, multicast packets are **not** supported.
  * ARP packets (including gratuitous requests and replies) are supported.
  * 802.3 frames and 802.1Q are **not** supported.
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

The TCP protocol is supported over IPv4. Server and client sockets are supported.

  * TCP header checksum is supported.
  * Multiple packets will be transmitted without waiting for an acknowledgement.
  * Lost packets will be retransmitted with exponential backoff, starting at
    a fixed delay of 100 ms.
  * After arriving at the TIME-WAIT state, sockets will close after a fixed delay of 10 s.
  * TCP urgent pointer is **not** supported; any urgent octets will be received alongside
    data octets.
  * Reassembly of out-of-order segments is **not** supported.
  * The status of TCP options is:
    * Maximum segment size option is supported.
    * Window scaling is **not** supported, and the maximum buffer size is 65536.
    * Timestamping is **not** supported.
    * Fast open is **not** supported.
  * Keepalive is **not** supported.

Installation
------------

To use the _smoltcp_ library in your project, add the following to `Cargo.toml`:

```toml
[dependencies]
smoltcp = "0.3"
```

The default configuration assumes a hosted environment, for ease of evaluation.
You probably want to disable default features and configure them one by one:

```toml
[dependencies]
smoltcp = { version = "0.3", default-features = false, features = ["..."] }
```

### Feature `std`

The `std` feature enables use of objects and slices owned by the networking stack through a
dependency on `std::boxed::Box` and `std::vec::Vec`. It also enables `smoltcp::phy::RawSocket`
and `smoltcp::phy::TapInterface`, if the platform supports it.

This feature is enabled by default.

### Feature `alloc`

The `alloc` feature enables use of objects owned by the networking stack through a dependency
on `alloc::boxed::Box`. This only works on nightly rustc.

### Feature `collections`

The `collections` feature enables use of slices owned by the networking stack through a dependency
on `collections::vec::Vec`. This only works on nightly rustc.

### Feature `log`

The `log` feature enables logging of events within the networking stack through
the [log crate][log]. The events are emitted with the TRACE log level.

[log]: https://crates.io/crates/log

This feature is enabled by default.

### Feature `verbose`

The `verbose` feature enables logging of events where the logging itself may incur very high
overhead. For example, emitting a log line every time an application reads or writes as little
as 1 octet from a socket is likely to overwhelm the application logic unless a `BufReader`
or `BufWriter` is used, which are of course not available on heap-less systems.

This feature is disabled by default.

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

### Fault injection

In order to demonstrate the response of _smoltcp_ to adverse network conditions, all examples
implement fault injection, available through command-line options:

  * The `--drop-chance` option randomly drops packets, with given probability in percents.
  * The `--corrupt-chance` option randomly mutates one octet in a packet, with given
    probability in percents.
  * The `--size-limit` option drops packets larger than specified size.
  * The `--tx-rate-limit` and `--rx-rate-limit` options set the amount of tokens for
    a token bucket rate limiter, in packets per bucket.
  * The `--shaping-interval` option sets the refill interval of a token bucket rate limiter,
    in milliseconds.

A good starting value for `--drop-chance` and `--corrupt-chance` is 15%. A good starting
value for `--?x-rate-limit` is 4 and `--shaping-interval` is 50 ms.

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

_examples/server.rs_ emulates a network host that can respond to requests.

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
  * TCP packets on port 6971 (`cat /dev/urandom | socat stdio tcp4-connect:192.168.69.1:6971`),
    which will be ignored.

The buffers are only 64 bytes long, for convenience of testing resource exhaustion conditions.

### examples/client.rs

_examples/client.rs_ emulates a network host that can initiate requests.

The host is assigned the hardware address `02-00-00-00-00-02` and IPv4 address `192.168.69.2`.

Read its [source code](/examples/client.rs), then run it as:

```sh
cargo run --example client -- tap0 ADDRESS PORT
```

It connects to the given address (not a hostname) and port (e.g. `socat stdio tcp4-listen 1234`),
and will respond with reversed chunks of the input indefinitely.

License
-------

_smoltcp_ is distributed under the terms of 0-clause BSD license.

See [LICENSE-0BSD](LICENSE-0BSD.txt) for details.
