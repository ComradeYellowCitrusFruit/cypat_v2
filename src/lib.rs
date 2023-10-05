/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

//! # A cyberpatriots scoring engine library
//! 
//! Provides a fairly simple interface for programming Cyberpatriots scoring engines for practice images. 
//! It provides many core facilities useful for writing a scoring engine, 
//! such as a simple system to handle vulnerabilities, a scoring report, 
//! and some optional facilities for handling a database of configuration files, 
//! or providing utilities for users, groups and packages.
//! 
//! ## Examples
//! 
//! Here's an example of a stupidly simple scoring engine.
//! ```rust
//! use cypat::{scorer, engine, settings};
//! use std::{fs::File, io::{BufRead, BufReader, Read}, string::{String, ToString}};
//! 
//! fn main() {
//!     let func = |x: Option<&mut file> | -> bool {
//!         match x {
//!             Some(file) => {
//!                 let mut string: String;
//!                 BufReader::new(file.clone()).read_line(&mut string);
//! 
//!                 if string == "Hello World" {
//!                     add_score_entry(0, 50, "Wrote Hello World.".to_string());
//!                     true
//!                 } else {
//!                     false
//!                 }
//!             },
//!             None => false,
//!         }
//!     };
//! 
//!     set_update_freq(1);
//!     set_completed_update_freq(1);
//!     add_file_vuln("example.txt", func);
//! 
//!     enter_engine();
//! }
//! ```

pub(crate) mod state; // Isolate the internals of the state off to it's own private corner of hell
pub mod scorer;
pub mod engine;
pub mod settings;

#[cfg(feature = "utility")]
pub mod util;

#[cfg(feature = "database")]
pub mod filesystem;