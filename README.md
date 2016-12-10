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

  * Regular 802.3 frames are supported.
  * 802.1Q is not supported.
  * Jumbo frames are not supported.
  * CRC calculation is not supported.
  * ARP packets are supported.
  * ARP probes or announcements are not supported.

### IP layer

IP is not supported yet.

### UDP layer

UDP is not supported yet.

### TCP layer

TCP is not supported yet.

Installation
------------

To use the _smoltcp_ library in your project, add the following to `Cargo.toml`:

```toml
[dependencies]
smoltcp = "0.1"
```

Usage example
-------------

```rust
TBD
```

License
-------

_smoltcp_ is distributed under the terms of both the MIT license
and the Apache License (Version 2.0).

See [LICENSE-APACHE](LICENSE-APACHE) and [LICENSE-MIT](LICENSE-MIT)
for details.
