//! Sliding-window replay protection for frame sequence numbers.

/// A sliding-window replay detector using a 128-bit bitmap.
///
/// Tracks the highest-seen sequence number and a window of the most recent
/// 128 sequence numbers. Sequence numbers at or below `(highest - 128)` are
/// rejected as too old. Previously-seen sequence numbers are rejected as replays.
pub struct ReplayWindow {
    highest: u64,
    bitmap: u128,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub const WINDOW_SIZE: u64 = 128;

    pub fn new() -> Self {
        Self {
            highest: 0,
            bitmap: 0,
        }
    }

    /// Check if a sequence number is acceptable (not a replay, not too old).
    /// If acceptable, marks it as seen and returns `true`.
    /// If rejected, returns `false` without modifying state.
    pub fn check_and_advance(&mut self, seq: u64) -> bool {
        if seq == 0 {
            return false; // seq 0 is reserved/invalid
        }

        if self.highest == 0 {
            // First packet.
            self.highest = seq;
            self.bitmap = 1;
            return true;
        }

        if seq > self.highest {
            let shift = seq - self.highest;
            if shift >= Self::WINDOW_SIZE {
                self.bitmap = 1;
            } else {
                self.bitmap = self.bitmap.checked_shl(shift as u32).unwrap_or(0) | 1;
            }
            self.highest = seq;
            return true;
        }

        let diff = self.highest - seq;
        if diff >= Self::WINDOW_SIZE {
            return false; // too old
        }

        let bit = 1u128 << diff;
        if self.bitmap & bit != 0 {
            return false; // replay
        }

        self.bitmap |= bit;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seq_zero_rejected() {
        let mut w = ReplayWindow::new();
        assert!(!w.check_and_advance(0));
    }

    #[test]
    fn first_packet_accepted() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_advance(1));
    }

    #[test]
    fn sequential_all_accepted() {
        let mut w = ReplayWindow::new();
        for i in 1..=200 {
            assert!(w.check_and_advance(i), "seq {i} should be accepted");
        }
    }

    #[test]
    fn duplicate_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_advance(5));
        assert!(!w.check_and_advance(5));
    }

    #[test]
    fn out_of_order_within_window() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_advance(1));
        assert!(w.check_and_advance(3));
        assert!(w.check_and_advance(2)); // out of order but within window
    }

    #[test]
    fn out_of_order_beyond_window_rejected() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_advance(1));
        assert!(w.check_and_advance(200)); // jump forward
        assert!(!w.check_and_advance(1)); // now too old (diff = 199 >= 128)
    }

    #[test]
    fn large_jump_resets_window() {
        let mut w = ReplayWindow::new();
        for i in 1..=10 {
            assert!(w.check_and_advance(i));
        }
        // Jump past window
        assert!(w.check_and_advance(500));
        // Old values rejected
        assert!(!w.check_and_advance(10));
        // New sequential values accepted
        assert!(w.check_and_advance(501));
    }

    #[test]
    fn window_boundary_exact() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_advance(1));
        assert!(w.check_and_advance(128)); // highest=128
        // seq 1: diff = 127, within window
        assert!(!w.check_and_advance(1)); // already seen
        // But seq 2 was never seen, diff = 126 < 128
        assert!(w.check_and_advance(2));
    }

    #[test]
    fn window_boundary_just_outside() {
        let mut w = ReplayWindow::new();
        assert!(w.check_and_advance(1));
        assert!(w.check_and_advance(129)); // highest=129, diff for seq=1 is 128 = WINDOW_SIZE
        assert!(!w.check_and_advance(1)); // exactly at boundary: rejected (>= WINDOW_SIZE)
    }

    #[test]
    fn interleaved_pattern() {
        let mut w = ReplayWindow::new();
        // Receive even numbers first
        for i in (2..=20).step_by(2) {
            assert!(w.check_and_advance(i));
        }
        // Then odd numbers (all within window)
        for i in (1..=19).step_by(2) {
            assert!(w.check_and_advance(i));
        }
        // All duplicates rejected
        for i in 1..=20 {
            assert!(!w.check_and_advance(i));
        }
    }
}
