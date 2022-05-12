# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- No unreleased changes.

## [0.8.1] - 2022-05-12

- Remove unused `rand_core` dep. ([#589](https://github.com/smoltcp-rs/smoltcp/pull/589))
- Use socklen_t instead of u32 for RawSocket bind() parameter. Fixes build on 32bit Android. ([#593](https://github.com/smoltcp-rs/smoltcp/pull/593))
- Propagate phy::RawSocket send errors to caller ([#588](https://github.com/smoltcp-rs/smoltcp/pull/588))
- Fix Interface set_hardware_addr, get_hardware_addr for ieee802154/6lowpan. ([#584](https://github.com/smoltcp-rs/smoltcp/pull/584))

## [0.8.0] - 2021-12-11

- Minimum Supported Rust Version (MSRV) **bumped** from 1.40 to 1.56
- Add support for IEEE 802.15.4 + 6LoWPAN medium ([#469](https://github.com/smoltcp-rs/smoltcp/pull/469))
- Add support for IP medium ([#401](https://github.com/smoltcp-rs/smoltcp/pull/401))
- Add `defmt` logging supprt ([#455](https://github.com/smoltcp-rs/smoltcp/pull/455))
- Add RNG infrastructure ([#547](https://github.com/smoltcp-rs/smoltcp/pull/547), [#573](https://github.com/smoltcp-rs/smoltcp/pull/573))
- Add `Context` struct that must be passed to some socket methods ([#500](https://github.com/smoltcp-rs/smoltcp/pull/500))
- Remove `SocketSet`, sockets are owned by `Interface` now. ([#557](https://github.com/smoltcp-rs/smoltcp/pull/557), [#571](https://github.com/smoltcp-rs/smoltcp/pull/571))
- TCP: Add Nagle's Algorithm. ([#500](https://github.com/smoltcp-rs/smoltcp/pull/500))
- TCP crash and correctness fixes:
    - Add Nagle's Algorithm. ([#500](https://github.com/smoltcp-rs/smoltcp/pull/500))
    - Window scaling fixes. ([#500](https://github.com/smoltcp-rs/smoltcp/pull/500))
    - Fix delayed ack causing ack not to be sent after 3 packets. ([#530](https://github.com/smoltcp-rs/smoltcp/pull/530))
    - Fix RTT estimation for RTTs longer than 1 second ([#538](https://github.com/smoltcp-rs/smoltcp/pull/538))
    - Fix infinite loop when remote side sets a MSS of 0 ([#538](https://github.com/smoltcp-rs/smoltcp/pull/538))
    - Fix infinite loop when retransmit when remote window is 0 ([#538](https://github.com/smoltcp-rs/smoltcp/pull/538))
    - Fix crash when receiving a FIN in SYN_SENT state ([#538](https://github.com/smoltcp-rs/smoltcp/pull/538))
    - Fix overflow crash when receiving a wrong ACK seq in SYN_RECEIVED state ([#538](https://github.com/smoltcp-rs/smoltcp/pull/538))
    - Fix overflow crash when initial sequence number is u32::MAX ([#538](https://github.com/smoltcp-rs/smoltcp/pull/538))
    - Fix infinite loop on challenge ACKs ([#542](https://github.com/smoltcp-rs/smoltcp/pull/542))
    - Reply with RST to invalid packets in SynReceived state.  ([#542](https://github.com/smoltcp-rs/smoltcp/pull/542))
    - Do not abort socket when receiving some invalid packets.  ([#542](https://github.com/smoltcp-rs/smoltcp/pull/542))
    - Make initial sequence number random.  ([#547](https://github.com/smoltcp-rs/smoltcp/pull/547))
    - Reply with RST to ACKs with invalid ackno in SYN_SENT. ([#522](https://github.com/smoltcp-rs/smoltcp/pull/522))
- ARP fixes to deal better with broken networks:
    - Fill cache only from ARP packets, not any packets. ([#544](https://github.com/smoltcp-rs/smoltcp/pull/544))
    - Fill cache only from ARP packets directed at us. ([#544](https://github.com/smoltcp-rs/smoltcp/pull/544))
    - Reject ARP packets with a source address not in the local network. ([#536](https://github.com/smoltcp-rs/smoltcp/pull/536), [#544](https://github.com/smoltcp-rs/smoltcp/pull/544))
    - Ignore unknown ARP packets. ([#544](https://github.com/smoltcp-rs/smoltcp/pull/544))
    - Flush neighbor cache on IP change ([#564](https://github.com/smoltcp-rs/smoltcp/pull/564))
- UDP: Add `close()` method to unbind socket. ([#475](https://github.com/smoltcp-rs/smoltcp/pull/475), [#482](https://github.com/smoltcp-rs/smoltcp/pull/482))
- DHCP client improvements:
    - Refactored implementation to improve reliability and RFC compliance ([#459](https://github.com/smoltcp-rs/smoltcp/pull/459))
    - Convert to socket ([#459](https://github.com/smoltcp-rs/smoltcp/pull/459))
    - Added `max_lease_duration` option ([#459](https://github.com/smoltcp-rs/smoltcp/pull/459))
    - Do not set the BROADCAST flag ([#548](https://github.com/smoltcp-rs/smoltcp/pull/548))
    - Add option to ignore NAKs ([#548](https://github.com/smoltcp-rs/smoltcp/pull/548))
- DHCP wire:
    - Fix DhcpRepr::buffer_len not accounting for lease time, router and subnet options ([#478](https://github.com/smoltcp-rs/smoltcp/pull/478))
    - Emit DNS servers in DhcpRepr ([#510](https://github.com/smoltcp-rs/smoltcp/pull/510))
    - Fix incorrect bit for BROADCAST flag ([#548](https://github.com/smoltcp-rs/smoltcp/pull/548))
- Improve resilience against packet ingress processing errors ([#281](https://github.com/smoltcp-rs/smoltcp/pull/281), [#483](https://github.com/smoltcp-rs/smoltcp/pull/483))
- Implement `std::error::Error` for `smoltcp::Error` ([#485](https://github.com/smoltcp-rs/smoltcp/pull/485))
- Update `managed` from 0.7 to 0.8 ([442](https://github.com/smoltcp-rs/smoltcp/pull/442))
- Fix incorrect timestamp in PCAP captures ([#513](https://github.com/smoltcp-rs/smoltcp/pull/513))
- Use microseconds instead of milliseconds in Instant and Duration ([#514](https://github.com/smoltcp-rs/smoltcp/pull/514))
- Expose inner `Device` in `PcapWriter` ([#524](https://github.com/smoltcp-rs/smoltcp/pull/524))
- Fix assert with any_ip + broadcast dst_addr. ([#533](https://github.com/smoltcp-rs/smoltcp/pull/533), [#534](https://github.com/smoltcp-rs/smoltcp/pull/534))
- Simplify PcapSink trait ([#535](https://github.com/smoltcp-rs/smoltcp/pull/535))
- Fix wrong operation order in FuzzInjector ([#525](https://github.com/smoltcp-rs/smoltcp/pull/525), [#535](https://github.com/smoltcp-rs/smoltcp/pull/535))

## [0.7.5] - 2021-06-28

- dhcpv4: emit DNS servers in repr ([#505](https://github.com/smoltcp-rs/smoltcp/pull/505))

## [0.7.4] - 2021-06-11

- tcp: fix "subtract sequence numbers with underflow" on remote window shrink. ([#490](https://github.com/smoltcp-rs/smoltcp/pull/490))
- tcp: fix substract with overflow when receiving a SYNACK with unincremented ACK number. ([#491](https://github.com/smoltcp-rs/smoltcp/pull/491))
- tcp: use nonzero initial sequence number to workaround misbehaving servers. ([#492](https://github.com/smoltcp-rs/smoltcp/pull/492))

## [0.7.3] - 2021-05-29

- Fix "unused attribute" error in recent nightlies.

## [0.7.2] - 2021-05-29

- iface: check for ipv4 subnet broadcast addrs everywhere ([#462](https://github.com/smoltcp-rs/smoltcp/pull/462))
- dhcp: always send parameter_request_list. ([#456](https://github.com/smoltcp-rs/smoltcp/pull/456))
- dhcp: Clear expiration time on reset. ([#456](https://github.com/smoltcp-rs/smoltcp/pull/456))
- phy: fix FaultInjector returning a too big buffer when simulating a drop on tx ([#463](https://github.com/smoltcp-rs/smoltcp/pull/463))
- tcp rtte: fix "attempt to multiply with overflow". ([#476](https://github.com/smoltcp-rs/smoltcp/pull/476))
- tcp: LastAck should only change to Closed on ack of fin. ([#477](https://github.com/smoltcp-rs/smoltcp/pull/477))
- wire/dhcpv4: account for lease time, router and subnet options in DhcpRepr::buffer_len ([#478](https://github.com/smoltcp-rs/smoltcp/pull/478))

## [0.7.1] - 2021-03-27

- ndisc: Fix NeighborSolicit incorrectly asking for src addr instead of dst addr ([419](https://github.com/smoltcp-rs/smoltcp/pull/419))
- dhcpv4: respect lease time from the server instead of renewing every 60 seconds. ([437](https://github.com/smoltcp-rs/smoltcp/pull/437))
- Fix build errors due to invalid combinations of features ([416](https://github.com/smoltcp-rs/smoltcp/pull/416), [447](https://github.com/smoltcp-rs/smoltcp/pull/447))
- wire/ipv4: make some functions const ([420](https://github.com/smoltcp-rs/smoltcp/pull/420))
- phy: fix BPF on OpenBSD ([421](https://github.com/smoltcp-rs/smoltcp/pull/421), [427](https://github.com/smoltcp-rs/smoltcp/pull/427))
- phy: enable RawSocket, TapInterface on Android ([435](https://github.com/smoltcp-rs/smoltcp/pull/435))
- phy: fix phy_wait for waits longer than 1 second ([449](https://github.com/smoltcp-rs/smoltcp/pull/449))

## [0.7.0] - 2021-01-20

- Minimum Supported Rust Version (MSRV) **bumped** from 1.36 to 1.40

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
[0.8.1]: https://github.com/smoltcp-rs/smoltcp/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/smoltcp-rs/smoltcp/compare/v0.7.0...v0.8.0
[0.7.5]: https://github.com/smoltcp-rs/smoltcp/compare/v0.7.4...v0.7.5
[0.7.4]: https://github.com/smoltcp-rs/smoltcp/compare/v0.7.3...v0.7.4
[0.7.3]: https://github.com/smoltcp-rs/smoltcp/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/smoltcp-rs/smoltcp/compare/v0.7.1...v0.7.2
[0.7.1]: https://github.com/smoltcp-rs/smoltcp/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/smoltcp-rs/smoltcp/compare/v0.6.0...v0.7.0
