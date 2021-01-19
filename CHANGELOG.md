# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

No unreleased changes yet

## [0.7.0] - 2021-01-20

### New features
- tcp: Allow distinguishing between graceful (FIN) and ungraceful (RST) close. On graceful close, `recv()` now returns `Error::Finished`. On ungraceful close, `Error::Illegal` is returned, as before. (#351)
- sockets: Add support for attaching async/await Wakers to sockets. Wakers are woken on socket state changes. (#394)
- tcp: Set retransmission timeout based on an RTT estimation, instead of the previously fixed 100ms. This improves performance on high-latency links, such as mobile networks. (#406)
- tcp: add Delayed ACK support. On by default, with a 10ms delay. (#404)
- ip: Process broadcast packets directed to the subnet's broadcast address, such as 192.168.1.255. Previously broadcast packets were
only processed when directed to the 255.255.255.255 address. (#377)

### Fixes
- udp,raw,icmp: Fix packet buffer panic caused by large payload (#332)
- dhcpv4: use offered ip in requested ip option (#310)
- dhcpv4: Re-export dhcp::clientv4::Config
- dhcpv4: Enable `proto-dhcpv4` feature by default. (#327)
- ethernet,arp: Allow for ARP retry during egress (#368)
- ethernet,arp: Only limit the neighbor cache rate after sending a request packet (#369)
- tcp: use provided ip for TcpSocket::connect instead of 0.0.0.0 (#329)
- tcp: Accept data packets in FIN_WAIT_2 state. (#350)
- tcp: Always send updated ack number in `ack_reply()`. (#353)
- tcp: allow sending ACKs in FinWait2 state. (#388)
- tcp: fix racey simultaneous close not sending FIN. (#398) 
- tcp: Do not send window updates in states that shouldn't do so (#360)
- tcp: Return RST to unexpected ACK in SYN-SENT state. (#367)
- tcp: Take MTU into account during TcpSocket dispatch. (#384)
- tcp: don't send data outside the remote window (#387)
- phy: Take Ethernet header into account for MTU of RawSocket and TapInterface. (#393)
- phy: add null terminator to c-string passed to libc API (#372)

### Quality of Life&trade; improvements 
- Update to Rust 2018 edition (#396)
- Migrate CI to Github Actions (#390)
- Fix clippy lints, enforce clippy in CI (#395, #402, #403, #405, #407)
- Use #[non_exhaustive] for enums and structs (#409, #411)
- Simplify lifetime parameters of sockets, SocketSet, EthernetInterface (#410, #413)

[Unreleased]: https://github.com/smoltcp-rs/smoltcp/compare/v0.7.0...HEAD
[0.7.0]: https://github.com/smoltcp-rs/smoltcp/compare/v0.6.0...v0.7.0
