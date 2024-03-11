/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

//! A cyberpatriots scoring engine library
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
//! fn main() {
//!     let mut engine = cypat::Engine::new();
//!     engine.add_file_vuln("world.txt", move |e, x| -> bool {
//!         match x {
//!             Some(file) => {
//!                 let mut string: std::string::String;
//!                 std::io::BufReader::new(file.clone()).read_line(&mut string);
//! 
//!                 if string == "Hello World" {
//!                     e.add_score_entry(0, 50, "Wrote Hello World.".to_string());
//!                     true
//!                 } else {
//!                     false
//!                 }
//!             },
//!             None => false,
//!         }
//!     });
//! 
//!     engine.add_hook(|x| {
//!         if x.entry_exists(0) {
//!             x.stop(false);
//!         }
//!     });
//! 
//!     engine.set_freq(2);
//!     engine.set_completed_freq(10);
//!     engine.enter();
//! }
//! ```

mod engine;
pub use engine::*;

#[cfg(feature = "utility")]
pub mod util;
