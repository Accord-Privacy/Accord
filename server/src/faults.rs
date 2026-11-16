//! Named fault points and invocation counters for tests (SPEC-01 section 10.1).
//!
//! Production code calls [`FaultPlan::check`] at each named point and
//! [`FaultPlan::count`] where a test needs to know how often something ran.
//! Without the `fault-injection` cargo feature both are no-ops and the plan
//! carries no state, so release builds contain no way to arm a fault.
//!
//! With the feature, a test arms a point with a [`FaultKind`]; the next
//! `check` of that point returns a database error of that class and disarms
//! the point. Point names used by the relay:
//!
//! - `repair:B1` to `repair:B23`, `repair:triggers` and `ledger:<name>`, passed
//!   to the database constructor through `DbOptions::faults`;
//! - request-path points (`admission:*`, `dm:lookup`, and `removal:delete`,
//!   the membership delete of the single removal routine of SPEC-01 REQ-50),
//!   armed at run time through `AppState::faults()`.
//!
//! Counters: `removal:hooks` counts runs of the removal-hook list of SPEC-01
//! REQ-34 step 6 (`admission::REMOVAL_HOOKS_COUNTER`).
//!
//! Pause points: production code awaits [`FaultPlan::pause`] where a test
//! must interleave another request (SPEC-03 REQ-29's join race). With the
//! feature, a test takes a `PauseGate` with `FaultPlan::hold`; the next
//! task that reaches the point waits there until the gate is released.
//! Points: `voice:join`, in `AppState::join_voice_channel` between the
//! membership check and the insert into the participant map.

/// The class of database error an armed fault point produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultKind {
    /// `SQLITE_CONSTRAINT` (primary result code 19): an ordinary statement
    /// failure that leaves the enclosing transaction usable.
    Constraint,
    /// `SQLITE_BUSY` (primary result code 5): an error after which SQLite may
    /// already have rolled back the whole transaction.
    Busy,
}

impl FaultKind {
    /// The SQLite result code the injected error reports.
    pub fn sqlite_code(self) -> i32 {
        match self {
            FaultKind::Constraint => 19,
            FaultKind::Busy => 5,
        }
    }
}

/// The set of armed fault points and counters shared by a relay instance.
/// Cloning shares the same state.
#[derive(Debug, Clone, Default)]
pub struct FaultPlan {
    #[cfg(feature = "fault-injection")]
    inner: std::sync::Arc<std::sync::Mutex<imp::Inner>>,
}

impl FaultPlan {
    /// An empty plan: nothing armed, every counter at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Fail the next `check` of `point`, if it is armed. Always `Ok` when the
    /// `fault-injection` feature is off.
    #[inline]
    pub fn check(&self, point: &str) -> Result<(), sqlx::Error> {
        #[cfg(feature = "fault-injection")]
        {
            if let Some(kind) = self.take(point) {
                return Err(sqlx::Error::Database(Box::new(imp::InjectedError::new(
                    point, kind,
                ))));
            }
        }
        let _ = point;
        Ok(())
    }

    /// Record one invocation of the counter `name`. A no-op without the
    /// `fault-injection` feature.
    #[inline]
    pub fn count(&self, name: &str) {
        #[cfg(feature = "fault-injection")]
        {
            let mut inner = imp::lock(&self.inner);
            *inner.counters.entry(name.to_string()).or_insert(0) += 1;
        }
        let _ = name;
    }

    /// Wait at `point` while a test holds it (`FaultPlan::hold`). Returns at
    /// once when the point is not held, and always without the
    /// `fault-injection` feature.
    #[inline]
    pub async fn pause(&self, point: &str) {
        #[cfg(feature = "fault-injection")]
        {
            let gate = imp::lock(&self.inner).holds.remove(point);
            if let Some(gate) = gate {
                gate.reached.notify_one();
                gate.release.notified().await;
            }
        }
        let _ = point;
    }
}

/// A held pause point (`FaultPlan::hold`): the test waits until a task
/// reaches the point, does what must happen meanwhile, then releases it.
#[cfg(feature = "fault-injection")]
#[derive(Debug, Default)]
pub struct PauseGate {
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(feature = "fault-injection")]
impl PauseGate {
    /// Wait until a task has reached the held point and is waiting there.
    pub async fn reached(&self) {
        self.reached.notified().await;
    }

    /// Let the waiting task (or the next one to arrive) continue.
    pub fn release(&self) {
        self.release.notify_one();
    }
}

#[cfg(feature = "fault-injection")]
impl FaultPlan {
    /// Hold `point`: the next task that reaches `pause(point)` waits there
    /// until the returned gate is released. Fires once, like `arm`.
    pub fn hold(&self, point: &str) -> std::sync::Arc<PauseGate> {
        let gate = std::sync::Arc::new(PauseGate::default());
        imp::lock(&self.inner)
            .holds
            .insert(point.to_string(), std::sync::Arc::clone(&gate));
        gate
    }

    /// Arm `point`: its next `check` fails with an error of class `kind`.
    pub fn arm(&self, point: &str, kind: FaultKind) {
        imp::lock(&self.inner).armed.insert(point.to_string(), kind);
    }

    /// Builder form of [`FaultPlan::arm`].
    pub fn armed(self, point: &str, kind: FaultKind) -> Self {
        self.arm(point, kind);
        self
    }

    /// True while `point` is armed and has not fired yet.
    pub fn is_armed(&self, point: &str) -> bool {
        imp::lock(&self.inner).armed.contains_key(point)
    }

    /// How many times the counter `name` was recorded.
    pub fn counter(&self, name: &str) -> u64 {
        imp::lock(&self.inner)
            .counters
            .get(name)
            .copied()
            .unwrap_or(0)
    }

    fn take(&self, point: &str) -> Option<FaultKind> {
        imp::lock(&self.inner).armed.remove(point)
    }
}

#[cfg(feature = "fault-injection")]
mod imp {
    use super::FaultKind;
    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::{Mutex, MutexGuard};

    #[derive(Debug, Default)]
    pub(super) struct Inner {
        pub(super) armed: HashMap<String, FaultKind>,
        pub(super) counters: HashMap<String, u64>,
        pub(super) holds: HashMap<String, std::sync::Arc<super::PauseGate>>,
    }

    /// Lock the plan, ignoring poisoning: the data is plain maps.
    pub(super) fn lock(inner: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
        match inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// A database error produced by an armed fault point. It reports the
    /// SQLite result code of its class, so code that classifies errors by
    /// code treats it exactly like a real one.
    #[derive(Debug)]
    pub(super) struct InjectedError {
        message: String,
        code: i32,
    }

    impl InjectedError {
        pub(super) fn new(point: &str, kind: FaultKind) -> Self {
            Self {
                message: format!("injected fault at {point}"),
                code: kind.sqlite_code(),
            }
        }
    }

    impl std::fmt::Display for InjectedError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.message)
        }
    }

    impl std::error::Error for InjectedError {}

    impl sqlx::error::DatabaseError for InjectedError {
        fn message(&self) -> &str {
            &self.message
        }

        fn code(&self) -> Option<Cow<'_, str>> {
            Some(self.code.to_string().into())
        }

        fn as_error(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn as_error_mut(&mut self) -> &mut (dyn std::error::Error + Send + Sync + 'static) {
            self
        }

        fn into_error(self: Box<Self>) -> Box<dyn std::error::Error + Send + Sync + 'static> {
            self
        }

        fn kind(&self) -> sqlx::error::ErrorKind {
            sqlx::error::ErrorKind::Other
        }
    }
}

#[cfg(all(test, feature = "fault-injection"))]
mod tests {
    use super::*;

    #[test]
    fn armed_point_fires_once_with_its_code() {
        let plan = FaultPlan::new().armed("repair:B6", FaultKind::Busy);
        assert!(plan.check("repair:B5").is_ok());
        let err = plan.check("repair:B6").unwrap_err();
        match err {
            sqlx::Error::Database(db) => assert_eq!(db.code().as_deref(), Some("5")),
            other => panic!("unexpected error {other:?}"),
        }
        assert!(plan.check("repair:B6").is_ok());
    }

    #[tokio::test]
    async fn held_point_waits_until_released() {
        let plan = FaultPlan::new();
        // Not held: no wait.
        plan.pause("voice:join").await;
        let gate = plan.hold("voice:join");
        let task = {
            let plan = plan.clone();
            tokio::spawn(async move { plan.pause("voice:join").await })
        };
        gate.reached().await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!task.is_finished());
        gate.release();
        tokio::time::timeout(std::time::Duration::from_secs(2), task)
            .await
            .expect("released")
            .unwrap();
        // Fired once.
        plan.pause("voice:join").await;
    }

    #[test]
    fn clones_share_state_and_count() {
        let plan = FaultPlan::new();
        let other = plan.clone();
        other.arm("x", FaultKind::Constraint);
        assert!(plan.is_armed("x"));
        plan.count("hooks");
        plan.count("hooks");
        assert_eq!(other.counter("hooks"), 2);
        assert_eq!(other.counter("none"), 0);
    }
}
