/// Linux proxy configuration implementation.
pub mod linux;
#[cfg(target_os = "macos")]
/// macOS proxy configuration implementation.
pub mod macos;
#[cfg(target_os = "windows")]
/// Windows proxy configuration implementation.
pub mod windows;

pub use linux::*;
#[cfg(target_os = "macos")]
pub use macos::*;
#[cfg(target_os = "windows")]
pub use windows::*;
