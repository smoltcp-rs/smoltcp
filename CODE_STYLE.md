# Code style

smoltcp does not follow the rustfmt code style because whitequark (the original
author of smoltcp) finds automated formatters annoying and impairing readability
just as much as improving it in different cases.

In general, format the things like the existing code and it'll be alright.
Here are a few things to watch out for, though:

## Ordering use statements

Use statements should be separated into two sections, uses from other crates and uses
from the current crate. The latter would ideally be sorted from most general
to most specific, but it's not very important.

```rust
use core::cell::RefCell;

use crate::{Error, Result};
use crate::phy::{self, DeviceCapabilities, Device};
```

## Wrapping function calls

Avoid rightwards drift. This is fine:

```rust
assert_eq!(iface.inner.process_ethernet(&mut socket_set, 0, frame.into_inner()),
           Ok(Packet::None));
```

This is also fine:

```rust
assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, 0,
    &IpAddress::Ipv4(Ipv4Address([0x7f, 0x00, 0x00, 0x01])),
    &IpAddress::Ipv4(remote_ip_addr)),
    Ok((remote_hw_addr, MockTxToken)));
```

This is not:

```rust
assert_eq!(iface.inner.lookup_hardware_addr(MockTxToken, 0,
                                            &IpAddress::Ipv4(Ipv4Address([0x7f, 0x00, 0x00, 0x01])),
                                            &IpAddress::Ipv4(remote_ip_addr)),
    Ok((remote_hw_addr, MockTxToken)));
```

## Wrapping function prototypes

A function declaration might be wrapped...

  * right after `,`,
  * right after `>`,
  * right after `)`,
  * right after `->`,
  * right before and after `where`.

Here's an artificial example, wrapped at 50 columns:

```rust
fn dispatch_ethernet<Tx, F>
                    (&mut self, tx_token: Tx,
                     timestamp: u64, f: F) ->
                    Result<()>
    where Tx: TxToken,
          F: FnOnce(EthernetFrame<&mut [u8]>)
{
    // ...
}
```

## Visually aligning tokens

This is fine:

```rust
struct State {
    rng_seed:    u32,
    refilled_at: u64,
    tx_bucket:   u64,
    rx_bucket:   u64,
}
```

This is also fine:

```rust
struct State {
    rng_seed: u32,
    refilled_at: u64,
    tx_bucket: u64,
    rx_bucket: u64,
}
```

It's OK to change between those if you touch that code anyway,
but avoid reformatting just for the sake of it.
