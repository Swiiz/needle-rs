use std::{error::Error, fmt::Display};

#[derive(Copy, Clone, Debug)]
pub enum FindProcessError {
    SnapshotError,
    NotFound,
}

#[derive(Copy, Clone, Debug)]
pub enum InjectionError {
    OpenProcessError,
    AllocateMemoryError,
    WriteProcessMemoryError,
    VirtualProtectProcessMemoryError,
    CreateRemoteThreadError,
}

impl Display for FindProcessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SnapshotError => write!(f, "Failed to create snapshot"),
            Self::NotFound => write!(f, "Process not found while processing snapshots"),
        }
    }
}

impl Display for InjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenProcessError => write!(f, "Failed to open process"),
            Self::AllocateMemoryError => write!(f, "Failed to allocate memory"),
            Self::WriteProcessMemoryError => write!(f, "Failed to write process memory"),
            Self::VirtualProtectProcessMemoryError => {
                write!(f, "Failed to virtual protect process memory")
            }
            Self::CreateRemoteThreadError => {
                write!(f, "Failed to create remote thread for execution")
            }
        }
    }
}

impl Error for FindProcessError {}
impl Error for InjectionError {}
