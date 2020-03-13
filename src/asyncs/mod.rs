//! Async primitives wrappers/reexports for (`Mutex`, `mpsc`, `RwLock`, `task::spawn`). Just
//! wrappers around which ever async library is available (`tokio`, `async-std`, embedded, etc).
pub mod sync;
pub mod task;
pub mod time;
