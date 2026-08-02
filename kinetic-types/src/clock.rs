use serde::{Deserialize, Serialize};

/// Represents a specific point in time on the Kinetic network using branded units.
///
/// # Time Hierarchy
///
/// - **Pulse**: 1 Drand Round (3 seconds)
/// - **Cycle**: 1,200 Pulses (1 Hour)
/// - **Epoch**: 28,800 Pulses (1 Day)
/// - **Orbit**: 7 Epochs (1 Week)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KineticTime {
    /// Number of completed 24-hour network Epochs (28,800 pulses each).
    pub epoch: u64,
    /// Number of completed 1-hour network Cycles within the current Epoch (1,200 pulses each, 0..23).
    pub cycle: u64,
    /// Number of completed 3-second Pulses within the current Cycle (0..1199).
    pub pulse: u64,
    /// Total number of pulses elapsed since network genesis.
    pub total_pulses: u64,
}

impl KineticTime {
    /// Creates a new [`KineticTime`] instance from an absolute Drand round number and a genesis round.
    ///
    /// If `current_drand_round` is less than `genesis_drand_round`,
    /// returns a time structure initialized to zero.
    #[allow(clippy::absurd_extreme_comparisons)]
    pub fn from_drand_round(current_drand_round: u64, genesis_drand_round: u64) -> Self {
        if current_drand_round < genesis_drand_round {
            return Self {
                epoch: 0,
                cycle: 0,
                pulse: 0,
                total_pulses: 0,
            };
        }

        let total_pulses = current_drand_round - genesis_drand_round;

        let epoch = total_pulses / 28_800;
        let remainder_after_epoch = total_pulses % 28_800;

        let cycle = remainder_after_epoch / 1_200;
        let pulse = remainder_after_epoch % 1_200;

        Self {
            epoch,
            cycle,
            pulse,
            total_pulses,
        }
    }

    /// Returns the number of completed 7-day network Orbits (1 Orbit = 7 Epochs).
    pub fn orbit(&self) -> u64 {
        self.epoch / 7
    }

    /// Formats the time into a branded aesthetic string.
    pub fn to_display_string(&self) -> String {
        format!(
            "Epoch {}, Cycle {} (Pulse {})",
            self.epoch, self.cycle, self.pulse
        )
    }
}
