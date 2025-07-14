#[derive(thiserror::Error, Debug, Copy, Clone)]
pub enum Error {
    #[error("Ran out of space in output buffer")]
    OutputBufferTooSmall,
    #[error("Failed to read file on disk")]
    ReadFile,
    #[error("Failed to parse pe headers")]
    ParsePE,
    #[error("Failed to relocate branch {from_rva:X} => {to_rva:X}")]
    RelocateBranch { from_rva: usize, to_rva: usize },
}

pub type Result<T> = core::result::Result<T, Error>;
