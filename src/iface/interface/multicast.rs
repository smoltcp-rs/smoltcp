use crate::{phy::Device, time::Instant};

use super::{Interface, IpPayload, Packet};

impl Interface<'_> {
    /// Poll the multicast queue and dispatch the next multicast packet if available
    pub(super) fn poll_multicast<D>(&mut self, device: &mut D) -> bool
    where
        D: Device + ?Sized,
    {
        // Dequeue empty multicast packets
        self.flush_multicast_queue();

        // If we did not find any still active multicast packets, we can stop here
        let Ok((meta, payload)) = self.multicast_queue.peek_mut() else {
            return true;
        };
        // If this panics, something went horibly wrong while checking for a valid multicast packet
        let next_ll_addr = meta.pop_next_ll_addr().unwrap();

        // Rehydrate the multicast packet from the queue
        let Ok(packet) = IpPayload::parse_unchecked(
            payload,
            meta.payload_type(),
            meta.header(),
            &self.inner.checksum_caps(),
        )
        .inspect_err(|_err| net_trace!("Parsing of queued packet has failed, dropping")) else {
            return false;
        };

        // Try to acquire a tx_token
        let Some(tx_token) = device.transmit(self.inner.now) else {
            return false; // Device is busy, retry later
        };

        let metadata = meta.meta();
        let header = *meta.header();
        let _ = self
            .inner
            .transmit_ip(
                tx_token,
                metadata,
                Packet::new_ipv6(header, packet),
                next_ll_addr,
                &mut self.fragmenter,
            )
            .inspect_err(|err| {
                net_trace!(
                    "Failed to transmit scheduled multicast transmission with reason {:?}",
                    err
                )
            });

        true
    }

    /// Request to poll again asap if there are still packets to be transmitted in the queue
    pub(super) fn poll_at_multicast(&mut self) -> Option<Instant> {
        if !self.multicast_queue.is_empty() {
            Some(self.inner.now)
        } else {
            None
        }
    }

    /// Remove empty multicast packets from the multicast queue
    fn flush_multicast_queue(&mut self) {
        // We may get an error if the queue is empty, but then flushing was succesful
        let _ = self.multicast_queue.dequeue_with(
            |meta, _packet| {
                if meta.finished() {
                    Ok(())
                } else {
                    Err(123)
                }
            },
        );
    }
}
