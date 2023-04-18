#!/usr/bin/env bash

set -eox pipefail

export DEFMT_LOG=trace

MSRV="1.65.0"

RUSTC_VERSIONS=(
    $MSRV
    "stable"
    "nightly"
)

FEATURES_TEST=(
    "default"
    "std,proto-ipv4"
    "std,medium-ethernet,phy-raw_socket,proto-ipv6,socket-udp,socket-dns"
    "std,medium-ethernet,phy-tuntap_interface,proto-ipv6,socket-udp"
    "std,medium-ethernet,proto-ipv4,proto-ipv4-fragmentation,socket-raw,socket-dns"
    "std,medium-ethernet,proto-ipv4,proto-igmp,socket-raw,socket-dns"
    "std,medium-ethernet,proto-ipv4,socket-udp,socket-tcp,socket-dns"
    "std,medium-ethernet,proto-ipv4,proto-dhcpv4,socket-udp"
    "std,medium-ethernet,medium-ip,medium-ieee802154,proto-ipv6,socket-udp,socket-dns"
    "std,medium-ethernet,proto-ipv6,socket-tcp"
    "std,medium-ethernet,medium-ip,proto-ipv4,socket-icmp,socket-tcp"
    "std,medium-ip,proto-ipv6,socket-icmp,socket-tcp"
    "std,medium-ieee802154,proto-sixlowpan,socket-udp"
    "std,medium-ieee802154,proto-sixlowpan,proto-sixlowpan-fragmentation,socket-udp"
    "std,medium-ieee802154,proto-rpl,proto-sixlowpan,proto-sixlowpan-fragmentation,socket-udp"
    "std,medium-ip,proto-ipv4,proto-ipv6,socket-tcp,socket-udp"
    "std,medium-ethernet,medium-ip,medium-ieee802154,proto-ipv4,proto-ipv6,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
)

FEATURES_TEST_NIGHTLY=(
    "alloc,medium-ethernet,proto-ipv4,proto-ipv6,socket-raw,socket-udp,socket-tcp,socket-icmp"
)

FEATURES_CHECK=(
    "medium-ip,medium-ethernet,medium-ieee802154,proto-ipv6,proto-ipv6,proto-igmp,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    "defmt,medium-ip,medium-ethernet,proto-ipv6,proto-ipv6,proto-igmp,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
    "defmt,alloc,medium-ip,medium-ethernet,proto-ipv6,proto-ipv6,proto-igmp,proto-dhcpv4,socket-raw,socket-udp,socket-tcp,socket-icmp,socket-dns,async"
)

test() {
    local version=$1
    rustup toolchain install $version

    for features in ${FEATURES_TEST[@]}; do
        cargo +$version test --no-default-features --features "$features"
    done

    if [[ $version == "nightly" ]]; then
        for features in ${FEATURES_TEST_NIGHTLY[@]}; do
            cargo +$version test --no-default-features --features "$features"
        done
    fi
}

check() {
    local version=$1
    rustup toolchain install $version

    export DEFMT_LOG="trace"

    for features in ${FEATURES_CHECK[@]}; do
        cargo +$version check --no-default-features --features "$features"
    done
}

clippy() {
    rustup toolchain install $MSRV
    rustup component add clippy --toolchain=$MSRV
    cargo +$MSRV clippy --tests --examples -- -D warnings
}

coverage() {
    for features in ${FEATURES_TEST[@]}; do
        cargo llvm-cov --no-report --no-default-features --features "$features"
    done
    cargo llvm-cov report --lcov --output-path lcov.info
}

if [[ $1 == "test" || $1 == "all" ]]; then
    if [[ -n $2 ]]; then
        if [[ $2 == "msrv" ]]; then
            test $MSRV
        else
            test $2
        fi
    else
        for version in ${RUSTC_VERSIONS[@]}; do
            test $version
        done
    fi
fi

if [[ $1 == "check" || $1 == "all" ]]; then
    if [[ -n $2 ]]; then
        if [[ $2 == "msrv" ]]; then
            check $MSRV
        else
            check $2
        fi
    else
        for version in ${RUSTC_VERSIONS[@]}; do
            check $version
        done
    fi
fi

if [[ $1 == "clippy" || $1 == "all" ]]; then
    clippy
fi

if [[ $1 == "coverage" || $1 == "all" ]]; then
    coverage
fi
