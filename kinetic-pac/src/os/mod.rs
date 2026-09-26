//! Operating system-specific proxy configurator modules.
//!
//! This module contains the highly privileged system integrations required to mutate
//! the host machine's networking environment. It leverages PowerShell on Windows,
//! `networksetup` on macOS, and `gsettings`/`kwriteconfig5` on Linux to forcibly
//! inject the `.kin` Proxy Auto-Configuration (PAC) script.

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
