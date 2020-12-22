# smoltcp

_smoltcp_ is a standalone, event-driven TCP/IP stack that is designed for bare-metal,
real-time systems. Its design goals are simplicity and robustness. Its design anti-goals
include complicated compile-time computations, such as macro or type tricks, even
at cost of performance degradation.

_smoltcp_ does not need heap allocation *at all*, is [extensively documented][docs],
and compiles on stable Rust 1.36 and later.

_smoltcp_ achieves [~Gbps of throughput](#examplesbenchmarkrs) when tested against
the Linux TCP stack in loopback mode.

[docs]: https://docs.rs/smoltcp/

## Features

_smoltcp_ is missing many widely deployed features, usually because no one implemented them yet.
To set expectations right, both implemented and omitted features are listed.

### Media layer

The only supported medium is Ethernet.

  * Regular Ethernet II frames are supported.
  * Unicast, broadcast and multicast packets are supported.
  * ARP packets (including gratuitous requests and replies) are supported.
  * ARP requests are sent at a rate not exceeding one per second.
  * Cached ARP entries expire after one minute.
  * 802.3 frames and 802.1Q are **not** supported.
  * Jumbo frames are **not** supported.

### IP layer

#### IPv4

  * IPv4 header checksum is generated and validated.
  * IPv4 time-to-live value is configurable per socket, set to 64 by default.
  * IPv4 default gateway is supported.
  * Routing outgoing IPv4 packets is supported, through a default gateway or a CIDR route table.
  * IPv4 fragmentation is **not** supported.
  * IPv4 options are **not** supported and are silently ignored.

#### IPv6

  * IPv6 hop-limit value is configurable per socket, set to 64 by default.
  * Routing outgoing IPv6 packets is supported, through a default gateway or a CIDR route table.
  * IPv6 hop-by-hop header is supported.
  * ICMPv6 parameter problem message is generated in response to an unrecognized IPv6 next header.
  * ICMPv6 parameter problem message is **not** generated in response to an unknown IPv6
    hop-by-hop option.

### IP multicast

#### IGMP

The IGMPv1 and IGMPv2 protocols are supported, and IPv4 multicast is available.

  * Membership reports are sent in response to membership queries at
    equal intervals equal to the maximum response time divided by the
    number of groups to be reported.

### ICMP layer

#### ICMPv4

The ICMPv4 protocol is supported, and ICMP sockets are available.

  * ICMPv4 header checksum is supported.
  * ICMPv4 echo replies are generated in response to echo requests.
  * ICMP sockets can listen to ICMPv4 Port Unreachable messages, or any ICMPv4 messages with
    a given IPv4 identifier field.
  * ICMPv4 protocol unreachable messages are **not** passed to higher layers when received.
  * ICMPv4 parameter problem messages are **not** generated.

#### ICMPv6

The ICMPv6 protocol is supported, but is **not** available via ICMP sockets.

  * ICMPv6 header checksum is supported.
  * ICMPv6 echo replies are generated in response to echo requests.
  * ICMPv6 protocol unreachable messages are **not** passed to higher layers when received.

#### NDISC

  * Neighbor Advertisement messages are generated in response to Neighbor Solicitations.
  * Router Advertisement messages are **not** generated or read.
  * Router Solicitation messages are **not** generated or read.
  * Redirected Header messages are **not** generated or read.

### UDP layer

The UDP protocol is supported over IPv4 and IPv6, and UDP sockets are available.

  * Header checksum is always generated and validated.
  * In response to a packet arriving at a port without a listening socket,
    an ICMP destination unreachable message is generated.

### TCP layer

The TCP protocol is supported over IPv4 and IPv6, and server and client TCP sockets are available.

  * Header checksum is generated and validated.
  * Maximum segment size is negotiated.
  * Window scaling is negotiated.
  * Multiple packets are transmitted without waiting for an acknowledgement.
  * Reassembly of out-of-order segments is supported, with no more than 4 or 32 gaps in sequence space.
  * Keep-alive packets may be sent at a configurable interval.
  * Retransmission timeout starts at a fixed interval of 100 ms and doubles every time.
  * Time-wait timeout has a fixed interval of 10 s.
  * User timeout has a configurable interval.
  * Selective acknowledgements are **not** implemented.
  * Delayed acknowledgements are **not** implemented.
  * Silly window syndrome avoidance is **not** implemented.
  * Nagle's algorithm is **not** implemented.
  * Congestion control is **not** implemented.
  * Timestamping is **not** supported.
  * Urgent pointer is **ignored**.
  * Probing Zero Windows is **not** implemented.
  * Packetization Layer Path MTU Discovery [PLPMTU](https://tools.ietf.org/rfc/rfc4821.txt) is **not** implemented.

## Installation

To use the _smoltcp_ library in your project, add the following to `Cargo.toml`:

```toml
[dependencies]
smoltcp = "0.5"
```

The default configuration assumes a hosted environment, for ease of evaluation.
You probably want to disable default features and configure them one by one:

```toml
[dependencies]
smoltcp = { version = "0.5", default-features = false, features = ["log"] }
```

### Feature `std`

The `std` feature enables use of objects and slices owned by the networking stack through a
dependency on `std::boxed::Box` and `std::vec::Vec`.

This feature is enabled by default.

### Feature `alloc`

The `alloc` feature enables use of objects owned by the networking stack through a dependency
on collections from the `alloc` crate. This only works on nightly rustc.

This feature is disabled by default.

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

### Features `phy-raw_socket` and `phy-tap_interface`

Enable `smoltcp::phy::RawSocket` and `smoltcp::phy::TapInterface`, respectively.

These features are enabled by default.

### Features `socket-raw`, `socket-udp`, and `socket-tcp`

Enable `smoltcp::socket::RawSocket`, `smoltcp::socket::UdpSocket`,
and `smoltcp::socket::TcpSocket`, respectively.

These features are enabled by default.

### Features `proto-ipv4` and `proto-ipv6`

Enable [IPv4] and [IPv6] respectively.

[IPv4]: https://tools.ietf.org/rfc/rfc791.txt
[IPv6]: https://tools.ietf.org/rfc/rfc8200.txt

## Hosted usage examples

_smoltcp_, being a freestanding networking stack, needs to be able to transmit and receive
raw frames. For testing purposes, we will use a regular OS, and run _smoltcp_ in
a userspace process. Only Linux is supported (right now).

On \*nix OSes, transmiting and receiving raw frames normally requires superuser privileges, but
on Linux it is possible to create a _persistent tap interface_ that can be manipulated by
a specific user:

```sh
sudo ip tuntap add name tap0 mode tap user $USER
sudo ip link set tap0 up
sudo ip addr add 192.168.69.100/24 dev tap0
sudo ip -6 addr add fe80::100/64 dev tap0
sudo ip -6 addr add fdaa::100/64 dev tap0
sudo ip -6 route add fe80::/64 dev tap0
sudo ip -6 route add fdaa::/64 dev tap0
```

It's possible to let _smoltcp_ access Internet by enabling routing for the tap interface:

```sh
sudo iptables -t nat -A POSTROUTING -s 192.168.69.0/24 -j MASQUERADE
sudo sysctl net.ipv4.ip_forward=1
sudo ip6tables -t nat -A POSTROUTING -s fdaa::/64 -j MASQUERADE
sudo sysctl -w net.ipv6.conf.all.forwarding=1
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
sudo ./target/debug/examples/tcpdump eth0
```

### examples/httpclient.rs

_examples/httpclient.rs_ emulates a network host that can initiate HTTP requests.

The host is assigned the hardware address `02-00-00-00-00-02`, IPv4 address `192.168.69.1`, and IPv6 address `fdaa::1`.

Read its [source code](/examples/httpclient.rs), then run it as:

```sh
cargo run --example httpclient -- tap0 ADDRESS URL
```

For example:

```sh
cargo run --example httpclient -- tap0 93.184.216.34 http://example.org/
```

or:

```sh
cargo run --example httpclient -- tap0 2606:2800:220:1:248:1893:25c8:1946 http://example.org/
```

It connects to the given address (not a hostname) and URL, and prints any returned response data.
The TCP socket buffers are limited to 1024 bytes to make packet traces more interesting.

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
is the other endpoint of the tap interface, `192.168.69.100`. It cannot reach itself because
packets entering a tap interface do not loop back.

### examples/server.rs

_examples/server.rs_ emulates a network host that can respond to basic requests.

The host is assigned the hardware address `02-00-00-00-00-01` and IPv4 address `192.168.69.1`.

Read its [source code](/examples/server.rs), then run it as:

```sh
cargo run --example server -- tap0
```

It responds to:

  * pings (`ping 192.168.69.1`);
  * UDP packets on port 6969 (`socat stdio udp4-connect:192.168.69.1:6969 <<<"abcdefg"`),
    where it will respond "hello" to any incoming packet;
  * TCP connections on port 6969 (`socat stdio tcp4-connect:192.168.69.1:6969`),
    where it will respond "hello" to any incoming connection and immediately close it;
  * TCP connections on port 6970 (`socat stdio tcp4-connect:192.168.69.1:6970 <<<"abcdefg"`),
    where it will respond with reversed chunks of the input indefinitely.
  * TCP connections on port 6971 (`socat stdio tcp4-connect:192.168.69.1:6971 </dev/urandom`),
    which will sink data. Also, keep-alive packets (every 1 s) and a user timeout (at 2 s)
    are enabled on this port; try to trigger them using fault injection.
  * TCP connections on port 6972 (`socat stdio tcp4-connect:192.168.69.1:6972 >/dev/null`),
    which will source data.

Except for the socket on port 6971. the buffers are only 64 bytes long, for convenience
of testing resource exhaustion conditions.

### examples/client.rs

_examples/client.rs_ emulates a network host that can initiate basic requests.

The host is assigned the hardware address `02-00-00-00-00-02` and IPv4 address `192.168.69.2`.

Read its [source code](/examples/client.rs), then run it as:

```sh
cargo run --example client -- tap0 ADDRESS PORT
```

It connects to the given address (not a hostname) and port (e.g. `socat stdio tcp4-listen:1234`),
and will respond with reversed chunks of the input indefinitely.

### examples/benchmark.rs

_examples/benchmark.rs_ implements a simple throughput benchmark.

Read its [source code](/examples/benchmark.rs), then run it as:

```sh
cargo run --release --example benchmark -- tap0 [reader|writer]
```

It establishes a connection to itself from a different thread and reads or writes a large amount
of data in one direction.

A typical result (achieved on a Intel Core i7-7500U CPU and a Linux 4.9.65 x86_64 kernel running
on a Dell XPS 13 9360 laptop) is as follows:

```
$ cargo run -q --release --example benchmark tap0 reader
throughput: 2.556 Gbps
$ cargo run -q --release --example benchmark tap0 writer
throughput: 5.301 Gbps
```

## Bare-metal usage examples

Examples that use no services from the host OS are necessarily less illustrative than examples
that do. Because of this, only one such example is provided.

### examples/loopback.rs

_examples/loopback.rs_ sets up _smoltcp_ to talk with itself via a loopback interface.
Although it does not require `std`, this example still requires the `alloc` feature to run, as well as `log`, `proto-ipv4` and `socket-tcp`.

Read its [source code](/examples/loopback.rs), then run it without `std`:

```sh
cargo run --example loopback --no-default-features --features="log proto-ipv4  socket-tcp alloc"
```

... or with `std` (in this case the features don't have to be explicitly listed):

```sh
cargo run --example loopback -- --pcap loopback.pcap
```

It opens a server and a client TCP socket, and transfers a chunk of data. You can examine
the packet exchange by opening `loopback.pcap` in [Wireshark].

If the `std` feature is enabled, it will print logs and packet dumps, and fault injection
is possible; otherwise, nothing at all will be displayed and no options are accepted.

[wireshark]: https://wireshark.org

## License

_smoltcp_ is distributed under the terms of 0-clause BSD license.

See [LICENSE-0BSD](LICENSE-0BSD.txt) for details.
