smoltcp
=======

_smoltcp_ is a standalone, event-driven TCP/IP stack that is designed for bare-metal,
real-time systems. Its design goals are simplicity and robustness. Its design anti-goals
include complicated compile-time computations, such as macro or type tricks, even
at cost of performance degradation.

_smoltcp_ does not need heap allocation *at all*, is [extensively documented][docs],
and compiles on stable Rust 1.19 and later.

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
dependency on `std::boxed::Box` and `std::vec::Vec`.

This feature is enabled by default.

### Features `raw_socket` and `tap_interface`

Enable `smoltcp::phy::RawSocket` and `smoltcp::phy::TapInterface`, respectively.

These features are enabled by default.

### Feature `alloc`

The `alloc` feature enables use of objects owned by the networking stack through a dependency
on `alloc::boxed::Box`. This only works on nightly rustc.

### Feature `collections`

The `collections` feature enables use of slices owned by the networking stack through a dependency
on `collections::vec::Vec`. This only works on nightly rustc.

### Feature `log`

The `log` feature enables logging of events within the networking stack through
the [log crate][log]. Normal events (e.g. buffer level or TCP state changes) are emitted with
the TRACE log level. Exceptional events (e.g. malformed packets) are emitted with
the DEBUG log level.

[log]: https://crates.io/crates/log

This feature is enabled by default.

### Feature `verbose`

The `verbose` feature enables logging of events where the logging itself may incur very high
overhead. For example, emitting a log line every time an application reads or writes as little
as 1 octet from a socket is likely to overwhelm the application logic unless a `BufReader`
or `BufWriter` is used, which are of course not available on heap-less systems.

This feature is disabled by default.

Hosted usage examples
---------------------

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

Note that packets dropped by the fault injector still get traced;
the  `rx: randomly dropping a packet` message indicates that the packet *above* it got dropped,
and the `tx: randomly dropping a packet` message indicates that the packet *below* it was.

### Packet dumps

All examples provide a `--pcap` option that writes a [libpcap] file containing a view of every
packet as it is seen by _smoltcp_.

[libpcap]: https://wiki.wireshark.org/Development/LibpcapFileFormat

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
    where it will respond "hello" to any incoming packet;
  * TCP packets on port 6969 (`socat stdio tcp4-connect:192.168.69.1:6969`),
    where it will respond "hello" to any incoming connection and immediately close it;
  * TCP packets on port 6970 (`socat stdio tcp4-connect:192.168.69.1:6970 <<<"abcdefg"`),
    where it will respond with reversed chunks of the input indefinitely.
  * TCP packets on port 6971 (`cat /dev/urandom | socat stdio tcp4-connect:192.168.69.1:6971`),
    which will be ignored.

Except for the socket on port 6971. the buffers are only 64 bytes long, for convenience
of testing resource exhaustion conditions.

### examples/client.rs

_examples/client.rs_ emulates a network host that can initiate requests.

The host is assigned the hardware address `02-00-00-00-00-02` and IPv4 address `192.168.69.2`.

Read its [source code](/examples/client.rs), then run it as:

```sh
cargo run --example client -- tap0 ADDRESS PORT
```

It connects to the given address (not a hostname) and port (e.g. `socat stdio tcp4-listen 1234`),
and will respond with reversed chunks of the input indefinitely.

### examples/ping.rs

_examples/ping.rs_ implements a minimal version of the `ping` utility using raw sockets.

The host is assigned the hardware address `02-00-00-00-00-02` and IPv4 address `192.168.69.1`.

Read its [source code](/examples/ping.rs), then run it as:

```sh
cargo run --example ping -- tap0 ADDRESS
```

It sends a series of 4 ICMP ECHO\_REQUEST packets to the given address at one second intervals and
prints out a status line on each valid ECHO\_RESPONSE received.

The first ECHO\_REQUEST packet is expected to be lost since arp\_cache is empty after startup;
the ECHO\_REQUEST packet is dropped and an ARP request is sent instead.

Currently, netmasks are not implemented, and so the only address this example can reach
is the other endpoint of the tap interface, `192.168.1.100`. It cannot reach itself because
packets entering a tap interface do not loop back.

Bare-metal usage examples
-------------------------

Examples that use no services from the host OS are necessarily less illustrative than examples
that do. Because of this, only one such example is provided.

### examples/loopback.rs

_examples/loopback.rs_ sets up _smoltcp_ to talk with itself via a loopback interface.
Although it does not require `std`, this example still requires the `collections` feature to run.

Read its [source code](/examples/loopback.rs), then run it without `std`:

```sh
cargo run --example loopback --no-default-features --features collections
```

... or with `std`:

```sh
cargo run --example loopback -- --pcap loopback.pcap
```

It opens a server and a client TCP socket, and transfers a chunk of data. You can examine
the packet exchange by opening `loopback.pcap` in [Wireshark].

If the `std` feature is enabled, it will print logs and packet dumps, and fault injection
is possible; otherwise, nothing at all will be displayed and no options are accepted.

[wireshark]: https://wireshark.org

License
-------

_smoltcp_ is distributed under the terms of 0-clause BSD license.

See [LICENSE-0BSD](LICENSE-0BSD.txt) for details.
