/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

mod user;
mod program;
mod filesystem;
pub use user::*;
pub use program::*;
pub use filesystem::*;

#[cfg(target_os = "linux")]
pub use libc::{uid_t, gid_t};

pub fn errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}