
# The MSRV that smoltcp compiles with.
MSRV := "1.65.0"

# `cargo check` and `cargo test`, usually used to check if a PR will succesfully check everything.
check-all: check test clippy check-nightly test-nightly

# `cargo check`
check:
    # These feature sets cannot run tests, so we only check they build.
    cargo +{{MSRV}} check --no-default-features --features "medium-ip,medium-ethernet,medium-ieee802154,proto-ipv6,proto-ipv6,proto-igmp,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    cargo +{{MSRV}} check --no-default-features --features "defmt,medium-ip,medium-ethernet,proto-ipv6,proto-ipv6,proto-igmp,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    cargo +{{MSRV}} check --no-default-features --features "defmt,alloc,medium-ip,medium-ethernet,proto-ipv6,proto-ipv6,proto-igmp,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"

# `cargo +nightly check`
check-nightly:
    # These feature sets cannot run tests, so we only check they build.
    cargo +nightly check --no-default-features --features "medium-ip,medium-ethernet,medium-ieee802154,proto-ipv6,proto-ipv6,proto-igmp,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    cargo +nightly check --no-default-features --features "defmt,medium-ip,medium-ethernet,proto-ipv6,proto-ipv6,proto-igmp,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    cargo +nightly check --no-default-features --features "defmt,alloc,medium-ip,medium-ethernet,proto-ipv6,proto-ipv6,proto-igmp,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"

# `cargo test`
test:
    # Test default features.
    cargo +{{MSRV}} test --features default
    # Test minimal featureset
    cargo +{{MSRV}} test --no-default-features --features "std,proto-ipv4"
    # Test features chosen to be as orthogonal as possible.
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ethernet,phy-raw_socket,proto-ipv6,socket-udp,socket-dns"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ethernet,phy-tuntap_interface,proto-ipv6,socket-udp"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ethernet,proto-ipv4,proto-ipv4-fragmentation,socket-raw,socket-dns"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ethernet,proto-ipv4,proto-igmp,socket-raw,socket-dns"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ethernet,proto-ipv4,socket-udp,socket-tcp,socket-dns"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ethernet,proto-ipv4,proto-dhcpv4,socket-udp"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ethernet,medium-ip,medium-ieee802154,proto-ipv6,socket-udp,socket-dns"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ethernet,proto-ipv6,socket-tcp"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ethernet,medium-ip,proto-ipv4,socket-icmp,socket-tcp"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ip,proto-ipv6,socket-icmp,socket-tcp"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ieee802154,proto-sixlowpan,socket-udp"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ieee802154,proto-sixlowpan,proto-sixlowpan-fragmentation,socket-udp"
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ip,proto-ipv4,proto-ipv6,socket-tcp,socket-udp"
    # Test features chosen to be as aggressive as possible.
    cargo +{{MSRV}} test --no-default-features --features "std,medium-ethernet,medium-ip,medium-ieee802154,proto-ipv4,proto-ipv6,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"

# `cargo +nightly test`
test-nightly:
    # Test default features.
    cargo +nightly test --features default
    # Test minimal featureset
    cargo +nightly test --features "std,proto-ipv4"
    # Test features chosen to be as orthogonal as possible.
    cargo +nightly test --no-default-features --features "std,medium-ethernet,phy-raw_socket,proto-ipv6,socket-udp,socket-dns"
    cargo +nightly test --no-default-features --features "std,medium-ethernet,phy-tuntap_interface,proto-ipv6,socket-udp"
    cargo +nightly test --no-default-features --features "std,medium-ethernet,proto-ipv4,proto-ipv4-fragmentation,socket-raw,socket-dns"
    cargo +nightly test --no-default-features --features "std,medium-ethernet,proto-ipv4,proto-igmp,socket-raw,socket-dns"
    cargo +nightly test --no-default-features --features "std,medium-ethernet,proto-ipv4,socket-udp,socket-tcp,socket-dns"
    cargo +nightly test --no-default-features --features "std,medium-ethernet,proto-ipv4,proto-dhcpv4,socket-udp"
    cargo +nightly test --no-default-features --features "std,medium-ethernet,medium-ip,medium-ieee802154,proto-ipv6,socket-udp,socket-dns"
    cargo +nightly test --no-default-features --features "std,medium-ethernet,proto-ipv6,socket-tcp"
    cargo +nightly test --no-default-features --features "std,medium-ethernet,medium-ip,proto-ipv4,socket-icmp,socket-tcp"
    cargo +nightly test --no-default-features --features "std,medium-ip,proto-ipv6,socket-icmp,socket-tcp"
    cargo +nightly test --no-default-features --features "std,medium-ieee802154,proto-sixlowpan,socket-udp"
    cargo +nightly test --no-default-features --features "std,medium-ieee802154,proto-sixlowpan,proto-sixlowpan-fragmentation,socket-udp"
    cargo +nightly test --no-default-features --features "std,medium-ip,proto-ipv4,proto-ipv6,socket-tcp,socket-udp"
    # Test features chosen to be as aggressive as possible.
    cargo +nightly test --no-default-features --features "std,medium-ethernet,medium-ip,medium-ieee802154,proto-ipv4,proto-ipv6,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    # Test the alloc feature in nightly.
    cargo +nightly test --no-default-features --features "alloc,medium-ethernet,proto-ipv4,proto-ipv6,socket-raw,socket-udp,socket-tcp,socket-icmp"

clippy:
    cargo clippy --tests --examples -- -D warnings
