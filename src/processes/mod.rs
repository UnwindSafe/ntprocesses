use nt::NtIteratorError;

pub mod nt;
pub mod snapshot;

/// Returns an iterator from a snapshot of all the processes.
pub fn get_from_snapshot() -> snapshot::SnapshotState {
    snapshot::SnapshotState::iter()
}

/// Returns an iterator from querying the system.
pub fn get_from_nt() -> Result<nt::NtProcessState, NtIteratorError> {
    nt::NtProcessState::iter()
}
