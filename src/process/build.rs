use std::path::PathBuf;
use thiserror::Error;
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, PROCESS_ACCESS_RIGHTS, PROCESS_CREATION_FLAGS,
};

use super::{Created, Process, ProcessError, Snapshot, NT};

#[derive(Error, Debug)]
pub enum ProcessBuilderError {
    #[error("Could not build the Process with these arguments.")]
    InvalidArgument,
    #[error(transparent)]
    ProcessError(#[from] ProcessError),
}

type Result<X> = std::result::Result<X, ProcessBuilderError>;

/// Marker type for process creation.
#[derive(Default)]
pub struct Create;
/// Marker type for attaching to existing process.
#[derive(Default)]
pub struct Attach;

#[derive(Default)]
pub struct ProcessBuilder<T> {
    name: Option<String>,
    process_id: Option<u32>,
    permissions: Option<PROCESS_ACCESS_RIGHTS>,
    file_path: Option<PathBuf>,
    creation_flags: PROCESS_CREATION_FLAGS,
    exe_args: Option<String>,
    _marker: std::marker::PhantomData<T>,
}

impl ProcessBuilder<Attach> {
    /// Set the permissions to use
    pub fn permissions(mut self, permissions: PROCESS_ACCESS_RIGHTS) -> Self {
        self.permissions = Some(permissions);
        self
    }

    pub fn process_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    pub fn process_id(mut self, pid: u32) -> Self {
        self.process_id = Some(pid);
        self
    }

    fn pre_build(&self) -> Result<()> {
        // we can't build a process that has mutually exclusive arugments.
        if self.process_id.is_some() && self.name.is_some() {
            return Err(ProcessBuilderError::InvalidArgument);
        }

        // we can't build a process that doesn't have permissions for type attach.
        if self.permissions.is_none() {
            return Err(ProcessBuilderError::InvalidArgument);
        }

        Ok(())
    }

    pub fn build_from_snapshot(self) -> Result<Process<Snapshot>> {
        self.pre_build()?;

        if let Some(name) = self.name {
            return Ok(Process::<Snapshot>::from_name(
                &name,
                self.permissions.unwrap(),
            )?);
        }

        if let Some(pid) = self.process_id {
            return Ok(Process::<Snapshot>::from_pid(
                pid,
                self.permissions.unwrap(),
            )?);
        }

        return Err(ProcessBuilderError::InvalidArgument);
    }

    pub fn build_from_nt(self) -> Result<Process<NT>> {
        self.pre_build()?;

        if let Some(name) = self.name {
            return Ok(Process::<NT>::from_name(&name, self.permissions.unwrap())?);
        }

        if let Some(pid) = self.process_id {
            return Ok(Process::<NT>::from_pid(pid, self.permissions.unwrap())?);
        }

        return Err(ProcessBuilderError::InvalidArgument);
    }
}

impl ProcessBuilder<Create> {
    pub fn file_path(mut self, path: PathBuf) -> Self {
        self.file_path = Some(path);
        self
    }

    /// Start the process suspended, shorthand for the flags method.
    pub fn suspended(mut self) -> Self {
        self.creation_flags |= CREATE_SUSPENDED;
        self
    }

    /// Provide process creation flags, like starting suspended for example.
    pub fn flags(mut self, flags: PROCESS_CREATION_FLAGS) -> Self {
        self.creation_flags |= flags;
        self
    }

    pub fn args(mut self, args: &str) -> Self {
        self.exe_args = Some(args.to_string());
        self
    }

    pub fn spawn(self) -> Result<Process<Created>> {
        // ensure that there is at least the file path.
        if self.file_path.is_none() {
            return Err(ProcessBuilderError::InvalidArgument);
        }

        Ok(Process::<Created>::from_path(
            self.file_path.unwrap(),
            &self.exe_args.unwrap_or_default(),
            self.creation_flags,
        )?)
    }
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;
    use pretty_assertions::assert_eq;
    use windows::Win32::System::Threading::PROCESS_ALL_ACCESS;

    #[test]
    fn builder_attach_snapshot() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<Snapshot>::get_current_process_id();

        ProcessBuilder::<Attach>::default()
            .permissions(PROCESS_ALL_ACCESS)
            .process_id(process_id)
            .build_from_snapshot()?;

        Ok(())
    }

    #[test]
    fn builder_attach_nt() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<NT>::get_current_process_id();

        ProcessBuilder::<Attach>::default()
            .permissions(PROCESS_ALL_ACCESS)
            .process_id(process_id)
            .build_from_nt()?;

        Ok(())
    }

    #[test]
    fn builder_create_process() -> Result<()> {
        // get the current process id for the current process.
        let process_id = Process::<Snapshot>::get_current_process_id();

        let target_process = ProcessBuilder::<Attach>::default()
            .permissions(PROCESS_ALL_ACCESS)
            .process_id(process_id)
            .build_from_snapshot()?;

        let process = ProcessBuilder::<Create>::default()
            .file_path(target_process.get_full_path()?)
            .suspended()
            .args("-test")
            .spawn()?;

        process.kill()?;

        Ok(())
    }

    #[test]
    fn builder_attach_invalid_config() {
        // get the current process id for the current process.
        let process_id = Process::<Snapshot>::get_current_process_id();

        let should_err = ProcessBuilder::<Attach>::default()
            .permissions(PROCESS_ALL_ACCESS)
            .process_id(process_id)
            .process_name("random.exe")
            .build_from_snapshot();

        assert_eq!(should_err.is_err(), true)
    }
}
