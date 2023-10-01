/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

pub(crate) mod state; // Isolate the internals of the state off to it's own private corner of hell
pub mod filesystem;
pub mod scorer;
pub mod engine;
pub mod util;