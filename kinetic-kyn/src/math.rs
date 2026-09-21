use crate::types::{Kyn, UKyn, CrystallizedKyn};

impl Kyn {
    /// Converts a `Kyn` number into a `UKyn` (Unix epoch timestamp in seconds).
    ///
    /// This is the secure method for deriving current time, as it bridges the 
    /// mathematical Kyn into standard Unix time for interoperability 
    /// (e.g., verifying `expires_at` in Identity Documents).
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_kyn::types::{Kyn, UKyn};
    ///
    /// let kyn = Kyn(100);
    /// // If genesis was at unix 1000
    /// let ukyn = kyn.to_ukyn(1000);
    /// assert_eq!(ukyn, UKyn(1100));
    /// ```
    pub fn to_ukyn(&self, genesis: u64) -> UKyn {
        UKyn(genesis.saturating_add(self.0))
    }

    /// Serializes the Kyn as an 8-byte array.
    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Deserializes the Kyn from an 8-byte array.
    pub fn from_be_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }

}

impl UKyn {
    /// Converts a `UKyn` (Unix epoch timestamp in seconds) into an estimated `Kyn` number.
    ///
    /// # Examples
    /// ```rust
    /// use kinetic_kyn::types::{Kyn, UKyn};
    ///
    /// let ukyn = UKyn(1100);
    /// // If genesis was at unix 1000:
    /// let kyn = ukyn.to_kyn(1000);
    /// assert_eq!(kyn, Kyn(100));
    /// ```
    pub fn to_kyn(&self, genesis: u64) -> Kyn {
        Kyn(self.0.saturating_sub(genesis))
    }

    /// Serializes the UKyn as an 8-byte array.
    pub fn to_be_bytes(&self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Deserializes the UKyn from an 8-byte array.
    pub fn from_be_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }
}

impl CrystallizedKyn {
    /// Creates a new [`CrystallizedKyn`] instance from an absolute network kyn number and a genesis kyn.
    ///
    /// If `current_kyn` is less than `genesis_kyn`,
    /// returns a time structure initialized to zero.
    // `current_kyn < genesis_kyn` is a valid safety guard even though both operands are
    // unsigned — CrystallizedKyn can return a stale kyn that predates network genesis during initial
    // sync. Clippy flags this comparison as absurd on u64 because it can never be negative,
    // but the guard is intentional and correct. Suppressed to avoid a misleading warning.
    #[allow(clippy::absurd_extreme_comparisons)]
    pub fn from_kyn(current_kyn: Kyn, genesis_kyn: Kyn) -> Self {
        if current_kyn.0 < genesis_kyn.0 {
            return Self {
                prism: 0,
                facet: 0,
                kyn: 0,
                total: 0,
            };
        }

        let total = current_kyn.0 - genesis_kyn.0;

        let prism = total / 86_400;
        let remainder_after_prism = total % 86_400;

        let facet = remainder_after_prism / 3_600;
        let kyn = remainder_after_prism % 3_600;

        // Safety invariants: integer division guarantees these ranges, but asserting
        // them in debug builds catches any future refactor that breaks the arithmetic.
        debug_assert!(facet < 24, "facet must be in 0..23, got {facet}");
        debug_assert!(kyn < 3_600, "kyn must be in 0..3599, got {kyn}");

        Self {
            prism,
            facet,
            kyn,
            total,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::types::{Kyn, UKyn, CrystallizedKyn};

    #[test]
    fn test_kyn_unix_conversion_roundtrip() {
        let genesis_time: u64 = 1_000;
        let kyn = Kyn(500);

        let unix_secs = kyn.to_ukyn(genesis_time);
        assert_eq!(unix_secs, UKyn(genesis_time + kyn.0));

        let recovered_kyn = unix_secs.to_kyn(genesis_time);
        assert_eq!(recovered_kyn, kyn);
    }

    #[test]
    fn test_from_kyn_boundaries() {
        let genesis = Kyn(1000);

        // Before genesis
        let t1 = CrystallizedKyn::from_kyn(Kyn(999), genesis);
        assert_eq!(t1.total, 0);

        // Exactly genesis
        let t2 = CrystallizedKyn::from_kyn(Kyn(1000), genesis);
        assert_eq!((t2.prism, t2.facet, t2.kyn, t2.total), (0, 0, 0, 0));

        // 1 Kyn later
        let t3 = CrystallizedKyn::from_kyn(Kyn(1001), genesis);
        assert_eq!((t3.prism, t3.facet, t3.kyn, t3.total), (0, 0, 1, 1));

        // Exactly 1 Facet (3,600 kyns)
        let t4 = CrystallizedKyn::from_kyn(Kyn(1000 + 3600), genesis);
        assert_eq!((t4.prism, t4.facet, t4.kyn, t4.total), (0, 1, 0, 3600));

        // Exactly 1 Prism (86,400 kyns)
        let t5 = CrystallizedKyn::from_kyn(Kyn(1000 + 86400), genesis);
        assert_eq!(
            (t5.prism, t5.facet, t5.kyn, t5.total),
            (1, 0, 0, 86400)
        );

        // Complex time: 1 Prism + 2 Facets + 3 Kyns = 86400 + 7200 + 3 = 93603
        let t6 = CrystallizedKyn::from_kyn(Kyn(1000 + 93603), genesis);
        assert_eq!(
            (t6.prism, t6.facet, t6.kyn, t6.total),
            (1, 2, 3, 93603)
        );
    }

    #[test]
    fn test_time_large_epochs() {
        let genesis = Kyn(0);

        // 1 Matrix = 7 Prisms = 7 × 86,400 = 604,800 kyns
        let t_matrix = CrystallizedKyn::from_kyn(Kyn(604_800), genesis);
        assert_eq!(t_matrix.prism / 7, 1);

        // 1 Lattice = 30 Prisms = 30 × 86,400 = 2,592,000 kyns
        let t_lattice = CrystallizedKyn::from_kyn(Kyn(2_592_000), genesis);
        assert_eq!(t_lattice.prism / 30, 1);

        // 1 Aeon = 365 Prisms = 365 × 86,400 = 31,536,000 kyns
        let t_aeon = CrystallizedKyn::from_kyn(Kyn(31_536_000), genesis);
        assert_eq!(t_aeon.prism / 365, 1);
    }

    #[test]
    fn test_kinetic_time_zero() {
        let genesis_kyn = 30579969;
        let genesis = Kyn(genesis_kyn);
        let time = CrystallizedKyn::from_kyn(genesis, genesis);
        assert_eq!(time.prism, 0);
        assert_eq!(time.facet, 0);
        assert_eq!(time.kyn, 0);
        assert_eq!(time.total, 0);
    }

    #[test]
    fn test_kinetic_time_pre_genesis() {
        let genesis_kyn = 30579969;
        let time =
            CrystallizedKyn::from_kyn(Kyn(genesis_kyn - 1), Kyn(genesis_kyn));
        assert_eq!(time.total, 0);
    }

    #[test]
    fn test_kinetic_time_complex() {
        let genesis_kyn = 30579969;
        let genesis = Kyn(genesis_kyn);

        // 1 day (86,400) + 2 hours (7,200) + 45 kyns = 93,645 total kyns
        let target_kyn = Kyn(genesis_kyn + 93_645);
        let time = CrystallizedKyn::from_kyn(target_kyn, genesis);

        assert_eq!(time.prism, 1);
        assert_eq!(time.facet, 2);
        assert_eq!(time.kyn, 45);
        assert_eq!(time.total, 93_645);
    }

    #[test]
    fn test_network_kyn_unix_conversion() {
        let kyn = Kyn(30_579_969);
        let drand_genesis = 1692803367;
        
        let unix_secs = kyn.to_ukyn(drand_genesis);
        assert_eq!(
            unix_secs,
            UKyn(drand_genesis + kyn.0)
        );
        let recovered = unix_secs.to_kyn(drand_genesis);
        assert_eq!(recovered, kyn);
    }
}
