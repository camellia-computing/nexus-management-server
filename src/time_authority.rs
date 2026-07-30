use std::{
    sync::{
        Arc,
        atomic::{AtomicI64, Ordering},
    },
    time::Instant,
};

/// Advances a database-backed time authority with process-monotonic elapsed time.
///
/// The database remains the durable high-water authority across restarts. The
/// monotonic component prevents expirations and leases from freezing when the
/// database clock moves backwards during a running process.
#[derive(Clone)]
pub(crate) struct PersistentTimeAuthority {
    origin: Arc<Instant>,
    seed_unix: i64,
    observed_high_water_unix: Arc<AtomicI64>,
    pub(crate) max_forward_jump_seconds: i64,
}

impl PersistentTimeAuthority {
    pub(crate) fn new(seed_unix: i64, max_forward_jump_seconds: i64) -> Self {
        Self {
            origin: Arc::new(Instant::now()),
            seed_unix,
            observed_high_water_unix: Arc::new(AtomicI64::new(seed_unix)),
            max_forward_jump_seconds,
        }
    }

    pub(crate) fn now(&self) -> i64 {
        self.now_at_elapsed(self.elapsed_seconds())
    }

    pub(crate) fn observe(&self, trusted_unix: i64) {
        self.observed_high_water_unix
            .fetch_max(trusted_unix, Ordering::AcqRel);
    }

    pub(crate) fn now_at_elapsed(&self, elapsed_seconds: i64) -> i64 {
        self.seed_unix
            .saturating_add(elapsed_seconds.max(0))
            .max(self.observed_high_water_unix.load(Ordering::Acquire))
    }

    fn elapsed_seconds(&self) -> i64 {
        self.origin.elapsed().as_secs().min(i64::MAX as u64) as i64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_time_advances_from_the_durable_seed() {
        let authority = PersistentTimeAuthority::new(1_000, 60);
        assert_eq!(authority.now_at_elapsed(0), 1_000);
        assert_eq!(authority.now_at_elapsed(31), 1_031);
        authority.observe(1_500);
        assert_eq!(authority.now_at_elapsed(32), 1_500);
        assert_eq!(authority.now_at_elapsed(600), 1_600);
        assert_eq!(authority.now_at_elapsed(31 * 60), 2_860);
        assert_eq!(authority.now_at_elapsed(8 * 60 * 60), 29_800);
    }
}
