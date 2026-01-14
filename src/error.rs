//! Error types for action-layer-driver

use thiserror::Error;

#[derive(Debug, Error)]
pub enum DriverError {
    #[error("Failed to parse puzzle bytes: {0}")]
    PuzzleParse(String),

    #[error("Failed to load puzzle into context: {0}")]
    PuzzleLoad(String),

    #[error("Failed to allocate CLVM node: {0}")]
    Alloc(String),

    #[error("Failed to serialize: {0}")]
    Serialize(String),

    #[error("Failed to construct action layer: {0}")]
    ActionLayer(String),

    #[error("Merkle proof not found for action hash")]
    MerkleProofNotFound,

    #[error("Invalid action index: {index}, only {count} actions available")]
    InvalidActionIndex { index: usize, count: usize },

    #[error("Launcher error: {0}")]
    Launcher(String),

    #[error("Singleton not yet launched")]
    NotLaunched,

    #[error("Singleton already launched")]
    AlreadyLaunched,

    #[error("Singleton has been melted (destroyed)")]
    Melted,

    #[error("Action failed: {0}")]
    ActionFailed(String),

    #[error("Broadcast failed: {0}")]
    Broadcast(String),

    #[error("Confirmation timeout")]
    ConfirmationTimeout,

    #[error("Network error: {0}")]
    Network(String),
}
