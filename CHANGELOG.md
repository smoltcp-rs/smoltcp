# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- Update `managed` from 0.7 to 0.8 ([442](https://github.com/smoltcp-rs/smoltcp/pull/442))

## [0.7.1] - 2021-03-27

- ndisc: Fix NeighborSolicit incorrectly asking for src addr instead of dst addr ([419](https://github.com/smoltcp-rs/smoltcp/pull/419))
- dhcpv4: respect lease time from the server instead of renewing every 60 seconds. ([437](https://github.com/smoltcp-rs/smoltcp/pull/437))
- Fix build errors due to invalid combinations of features ([416](https://github.com/smoltcp-rs/smoltcp/pull/416), [447](https://github.com/smoltcp-rs/smoltcp/pull/447))
- wire/ipv4: make some functions const ([420](https://github.com/smoltcp-rs/smoltcp/pull/420))
- phy: fix BPF on OpenBSD ([421](https://github.com/smoltcp-rs/smoltcp/pull/421), [427](https://github.com/smoltcp-rs/smoltcp/pull/427))
- phy: enable RawSocket, TapInterface on Android ([435](https://github.com/smoltcp-rs/smoltcp/pull/435))
- phy: fix phy_wait for waits longer than 1 second ([449](https://github.com/smoltcp-rs/smoltcp/pull/449))

## [0.7.0] - 2021-01-20

Minimum Supported Rust Version (MSRV) **bumped** from 1.36 to 1.40

### New features
- tcp: Allow distinguishing between graceful (FIN) and ungraceful (RST) close. On graceful close, `recv()` now returns `Error::Finished`. On ungraceful close, `Error::Illegal` is returned, as before. ([351](https://github.com/smoltcp-rs/smoltcp/pull/351))
- sockets: Add support for attaching async/await Wakers to sockets. Wakers are woken on socket state changes. ([394](https://github.com/smoltcp-rs/smoltcp/pull/394))
- tcp: Set retransmission timeout based on an RTT estimation, instead of the previously fixed 100ms. This improves performance on high-latency links, such as mobile networks. ([406](https://github.com/smoltcp-rs/smoltcp/pull/406))
- tcp: add Delayed ACK support. On by default, with a 10ms delay. ([404](https://github.com/smoltcp-rs/smoltcp/pull/404))
- ip: Process broadcast packets directed to the subnet's broadcast address, such as 192.168.1.255. Previously broadcast packets were
only processed when directed to the 255.255.255.255 address. ([377](https://github.com/smoltcp-rs/smoltcp/pull/377))

### Fixes
- udp,raw,icmp: Fix packet buffer panic caused by large payload ([332](https://github.com/smoltcp-rs/smoltcp/pull/332))
- dhcpv4: use offered ip in requested ip option ([310](https://github.com/smoltcp-rs/smoltcp/pull/310))
- dhcpv4: Re-export dhcp::clientv4::Config
- dhcpv4: Enable `proto-dhcpv4` feature by default. ([327](https://github.com/smoltcp-rs/smoltcp/pull/327))
- ethernet,arp: Allow for ARP retry during egress ([368](https://github.com/smoltcp-rs/smoltcp/pull/368))
- ethernet,arp: Only limit the neighbor cache rate after sending a request packet ([369](https://github.com/smoltcp-rs/smoltcp/pull/369))
- tcp: use provided ip for TcpSocket::connect instead of 0.0.0.0 ([329](https://github.com/smoltcp-rs/smoltcp/pull/329))
- tcp: Accept data packets in FIN_WAIT_2 state. ([350](https://github.com/smoltcp-rs/smoltcp/pull/350))
- tcp: Always send updated ack number in `ack_reply()`. ([353](https://github.com/smoltcp-rs/smoltcp/pull/353))
- tcp: allow sending ACKs in FinWait2 state. ([388](https://github.com/smoltcp-rs/smoltcp/pull/388))
- tcp: fix racey simultaneous close not sending FIN. ([398](https://github.com/smoltcp-rs/smoltcp/pull/398)) 
- tcp: Do not send window updates in states that shouldn't do so ([360](https://github.com/smoltcp-rs/smoltcp/pull/360))
- tcp: Return RST to unexpected ACK in SYN-SENT state. ([367](https://github.com/smoltcp-rs/smoltcp/pull/367))
- tcp: Take MTU into account during TcpSocket dispatch. ([384](https://github.com/smoltcp-rs/smoltcp/pull/384))
- tcp: don't send data outside the remote window ([387](https://github.com/smoltcp-rs/smoltcp/pull/387))
- phy: Take Ethernet header into account for MTU of RawSocket and TapInterface. ([393](https://github.com/smoltcp-rs/smoltcp/pull/393))
- phy: add null terminator to c-string passed to libc API ([372](https://github.com/smoltcp-rs/smoltcp/pull/372))

### Quality of Life&trade; improvements 
- Update to Rust 2018 edition ([396](https://github.com/smoltcp-rs/smoltcp/pull/396))
- Migrate CI to Github Actions ([390](https://github.com/smoltcp-rs/smoltcp/pull/390))
- Fix clippy lints, enforce clippy in CI ([395](https://github.com/smoltcp-rs/smoltcp/pull/395), [402](https://github.com/smoltcp-rs/smoltcp/pull/402), [403](https://github.com/smoltcp-rs/smoltcp/pull/403), [405](https://github.com/smoltcp-rs/smoltcp/pull/405), [407](https://github.com/smoltcp-rs/smoltcp/pull/407))
- Use #[non_exhaustive] for enums and structs ([409](https://github.com/smoltcp-rs/smoltcp/pull/409), [411](https://github.com/smoltcp-rs/smoltcp/pull/411))
- Simplify lifetime parameters of sockets, SocketSet, EthernetInterface ([410](https://github.com/smoltcp-rs/smoltcp/pull/410), [413](https://github.com/smoltcp-rs/smoltcp/pull/413))

[Unreleased]: https://github.com/smoltcp-rs/smoltcp/compare/v0.7.0...HEAD
[0.7.1]: https://github.com/smoltcp-rs/smoltcp/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/smoltcp-rs/smoltcp/compare/v0.6.0...v0.7.0
