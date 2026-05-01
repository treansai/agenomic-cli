//! Hybrid Logical Clock (HLC).
//!
//! Implementation follows Kulkarni et al., 2014 ("Logical Physical Clocks").

use serde::{Deserialize, Serialize};

/// A 16-byte hybrid logical clock value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hlc {
    /// Wall-clock milliseconds since UNIX epoch.
    pub physical_ms: u64,
    /// Logical counter incremented within the same millisecond.
    pub logical: u32,
    /// Node identifier (used to break ties between different writers).
    pub node_id: u32,
}

impl Hlc {
    /// Construct a new HLC.
    pub fn new(physical_ms: u64, logical: u32, node_id: u32) -> Self {
        Self {
            physical_ms,
            logical,
            node_id,
        }
    }

    /// Advance after receiving an event with `received` clock at local wall
    /// time `now_ms`.
    ///
    /// ```
    /// # use agentlock_atep::clock::Hlc;
    /// let local = Hlc::new(100, 0, 1);
    /// let recv = Hlc::new(150, 5, 2);
    /// let next = local.tick_after(recv, 120);
    /// assert!(next > local && next > recv);
    /// ```
    pub fn tick_after(self, received: Hlc, now_ms: u64) -> Hlc {
        let max_phys = std::cmp::max(
            std::cmp::max(self.physical_ms, received.physical_ms),
            now_ms,
        );
        let logical = if max_phys == self.physical_ms && max_phys == received.physical_ms {
            std::cmp::max(self.logical, received.logical) + 1
        } else if max_phys == self.physical_ms {
            self.logical + 1
        } else if max_phys == received.physical_ms {
            received.logical + 1
        } else {
            0
        };
        Hlc {
            physical_ms: max_phys,
            logical,
            node_id: self.node_id,
        }
    }

    /// Tick locally (no received event).
    pub fn tick(self, now_ms: u64) -> Hlc {
        if now_ms > self.physical_ms {
            Hlc {
                physical_ms: now_ms,
                logical: 0,
                node_id: self.node_id,
            }
        } else {
            Hlc {
                physical_ms: self.physical_ms,
                logical: self.logical + 1,
                node_id: self.node_id,
            }
        }
    }

    /// Encode as 16 little-endian bytes (8 physical + 4 logical + 4 node).
    pub fn to_le_bytes(self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&self.physical_ms.to_le_bytes());
        out[8..12].copy_from_slice(&self.logical.to_le_bytes());
        out[12..16].copy_from_slice(&self.node_id.to_le_bytes());
        out
    }

    /// Decode from 16 little-endian bytes.
    pub fn from_le_bytes(bytes: [u8; 16]) -> Self {
        let physical_ms = u64::from_le_bytes(bytes[0..8].try_into().unwrap_or([0; 8]));
        let logical = u32::from_le_bytes(bytes[8..12].try_into().unwrap_or([0; 4]));
        let node_id = u32::from_le_bytes(bytes[12..16].try_into().unwrap_or([0; 4]));
        Self {
            physical_ms,
            logical,
            node_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_local_advances_physical() {
        let h = Hlc::new(100, 5, 1).tick(200);
        assert_eq!(h.physical_ms, 200);
        assert_eq!(h.logical, 0);
    }

    #[test]
    fn tick_local_increments_logical_when_clock_lags() {
        let h = Hlc::new(100, 5, 1).tick(50);
        assert_eq!(h.physical_ms, 100);
        assert_eq!(h.logical, 6);
    }

    #[test]
    fn tick_after_picks_max_physical() {
        let local = Hlc::new(100, 1, 1);
        let recv = Hlc::new(200, 10, 2);
        let h = local.tick_after(recv, 50);
        assert_eq!(h.physical_ms, 200);
        assert_eq!(h.logical, 11);
    }

    #[test]
    fn roundtrip_le_bytes() {
        let h = Hlc::new(0xDEADBEEFCAFEu64, 0xAA55_AA55, 0x1234_5678);
        let b = h.to_le_bytes();
        let r = Hlc::from_le_bytes(b);
        assert_eq!(h, r);
    }
}
