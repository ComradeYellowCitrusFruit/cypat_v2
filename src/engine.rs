/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

//! The Engine Structure itself
//! 
//! This is the main module of this library.
//! It contains the [`Engine`] type, and some supporting structs and enums, [`AppData`], and [`InstallMethod`].
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

use std::{
    fs::File, 
    string::String, 
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering}, 
        Arc, 
        Mutex
    }, 
    thread::sleep, 
    time::Duration
};

/// Contains package install method.
#[derive(Clone, Copy)]
pub enum InstallMethod {
    Default,
    PackageManager,
    #[cfg(target_os = "windows")]
    WinGet,
    #[cfg(target_os = "linux")]
    Snap,
    #[cfg(target_os = "linux")]
    Flatpak,
    ManualInstall,
}

/// Contains some simple data regarding applications or packages
/// 
/// Contains some basic information regarding applications or packages.
/// Somewhat useful, particularly for looking up package information on Linux.
#[derive(Clone)]
pub struct AppData {
    pub install_method: InstallMethod,
    pub name: String,
}

#[derive(Clone)]
pub(crate) struct UserData {
    pub(crate) name: String,
}

pub(crate) enum Condition {
    FileVuln(String, Box<dyn FnMut(&mut Engine, Option<&mut File>) -> bool + Send + Sync>),
    AppVuln(AppData, Box<dyn FnMut(&mut Engine, AppData) -> bool + Send + Sync>),
    UserVuln(UserData, Box<dyn FnMut(&mut Engine, &str) -> bool + Send + Sync>),
    CustomVuln(Box<dyn FnMut(&mut Engine) -> bool + Send + Sync>),
}

pub struct Engine {
    is_running: AtomicBool,
    score: Arc<Mutex<Vec<(u64, i32, String)>>>,
    vulns: Arc<Mutex<Vec<(Condition, bool)>>>,
    incomplete_freq: AtomicU64,
    complete_freq: AtomicU64,
    in_execution: AtomicBool,
    step_iter: AtomicU64,
}

impl Engine {
    /// Create a new engine
    /// 
    /// Create a new engine, using default values, and no scores or vulnerabilities.
    pub fn new() -> Engine {
        Engine {
            is_running: AtomicBool::new(false),
            score: Arc::new(Mutex::new(Vec::new())),
            vulns: Arc::new(Mutex::new(Vec::new())),
            incomplete_freq: AtomicU64::new(5),
            complete_freq: AtomicU64::new(10),
            in_execution: AtomicBool::new(false),
            step_iter: AtomicU64::new(0),
        }
    }

    pub(crate) fn add_vuln(&mut self, vuln: Condition) {
        match self.vulns.lock() {
            Ok(mut g) => g.push((vuln, false)),
            Err(g) => panic!("{}", g),
        }
    }

    /// Register a file vulnerability
    /// 
    /// Register a file vulnerability.
    /// This takes the form of a function/closure that takes an [`&mut Engine`][`Engine`], and a [`Option<&mut File>`], and returns a [`bool`].
    /// 
    /// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
    /// More on that in [`Engine::update`] and [`Engine::enter`]
    pub fn add_file_vuln<F, S>(&mut self, name: S, f: F)
    where 
        F: FnMut(&mut Self, Option<&mut File>) -> bool + Send + Sync + 'static, // Whiny ass compiler
        S: ToString,
    {
        self.add_vuln(Condition::FileVuln(name.to_string(), Box::new(f) as Box<dyn FnMut(&mut Self, Option<&mut File>) -> bool + Send + Sync>));
    }

    /// Register a package/app vulnerability
    /// 
    /// Register a package/app vulnerability.
    /// This takes the form of a function/closure that takes an [`&mut Engine`][`Engine`], and an [`AppData`], and returns a [`bool`].
    /// 
    /// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
    /// More on that in [`Engine::update`] and [`Engine::enter`]    
    pub fn add_app_vuln<F, S>(&mut self, name: S, install_method: InstallMethod, f: F)
    where 
        F: FnMut(&mut Self, AppData) -> bool + Send + Sync + 'static, // Whiny ass compiler
        S: ToString,
    {
        let ad = AppData {
            name: name.to_string(),
            install_method: install_method,
        };

        self.add_vuln(Condition::AppVuln(ad, Box::new(f) as Box<dyn FnMut(&mut Self, AppData) -> bool + Send + Sync>));
    }

    /// Register a user vulnerability
    /// 
    /// Register a user vulnerability.
    /// This takes the form of a function/closure that takes a [`&mut Engine`][`Engine`], and a [`str`], and returns a [`bool`].
    /// 
    /// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
    /// More on that in [`Engine::update`] and [`Engine::enter`]
    pub fn add_user_vuln<F, S>(&mut self, name: S, f: F)
    where 
        F: FnMut(&mut Self, &str) -> bool + Send + Sync + 'static, // Whiny ass compiler
        S: ToString,
    {
        let ud = UserData {
            name: name.to_string(),
        };

        self.add_vuln(Condition::UserVuln(ud, Box::new(f) as Box<dyn FnMut(&mut Self, &str) -> bool + Send + Sync>));
    }

    /// Register a miscellaneous vulnerability
    /// 
    /// Register a miscellaneous vulnerability.
    /// This takes the form of a function/closure that takes only a [`&mut Engine`][`Engine`], and returns a [`bool`].
    /// 
    /// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
    /// More on that in [`Engine::update`] and [`Engine::enter`]
    pub fn add_misc_vuln<F>(&mut self, f: F)
    where
        F: FnMut(&mut Self) -> bool + Send + Sync + 'static,
    {
        self.add_vuln(Condition::CustomVuln(Box::new(f) as Box<dyn FnMut(&mut Self) -> bool + Send + Sync>));
    }

    /// Register a hook vulnerability
    /// 
    /// Register a hook vulnerability, which takes the form of a closure that takes a [`&mut Engine`][`Engine`] as it's only parameter.
    /// In reality this registers a miscellaneous vulnerability (see [`Engine::add_misc_vuln`]).
    /// This miscellaneous vulnerability is literally just a call to the hook that discards it's return, and returns false.
    pub fn add_hook<F, T>(&mut self, f: F)
    where
        F: FnMut(&mut Self) -> T + Send + Sync + 'static,
    {
        let mut boxed_f = Box::new(f);
        self.add_misc_vuln(move |x: &mut Engine| {
            let _ = boxed_f(x);
            false
        })
    }

    /// Sets the frequency in seconds at which the engine is updated.
    /// 
    /// Sets the frequency in seconds at which [`Engine::update`] is called, if using [`Engine::enter`].
    /// 
    /// This is handled as a private variable called [`incomplete_freq`][`Engine::set_freq`]
    pub fn set_freq(&mut self, frequency: u64) {
        self.incomplete_freq.store(frequency, Ordering::SeqCst);
    }

    /// Sets the frequency in iterations of engine updates that completed vulnerabilities are reviewed.
    /// 
    /// Sets the frequency in iterations of engine updates that completed vulnerabilities are re-executed.
    /// This value is important even if you don't use [`Engine::enter`] because of the way it is interpreted by [`Engine::update`]
    /// 
    /// Internally this is handled as a variable called [`complete_freq`][`Engine::set_completed_freq`]
    pub fn set_completed_freq(&mut self, frequency: u64) {
        self.complete_freq.store(frequency, Ordering::SeqCst);
    }

    /// Adds an entry to the score report, with an ID, a score value, and an explanation
    /// 
    /// Adds an entry to the score report, with an ID, a score value, and an explanation.
    /// If an entry exists with the same ID, it instead changes the score and explanation
    pub fn add_score(&mut self, id: u64, add: i32, reason: String) {
        match self.score.lock() {
            Ok(mut g) => { 
                for s in g.iter_mut() {
                    if s.0 == id {
                        s.1 = add;
                        s.2 = reason;
                        return;
                    }
                }

                g.push((id, add, reason));
            },
            Err(g) => panic!("{}", g),
        }
    }

    /// Removes the entry identified
    pub fn remove_score(&mut self, id: u64) -> Result<(), ()> {
        match self.score.lock() {
            Ok(mut g) => {
                for (idx, (id_of_val, _, _)) in (*g).clone().into_iter().enumerate() {
                    if id_of_val == id {
                        (*g).remove(idx);
                        return Ok(());
                    }
                }

                Err(())
            },
            Err(g) => panic!("{}", g),
        }
    }

    /// Generates a list of score entries
    /// Generates a vector containing the explanation and value of each score entry in order
    pub fn generate_score_report(&mut self) -> Vec<(String, i32)> {
        match self.score.lock() {
            Ok(g) => {
                let mut report = Vec::with_capacity((*g).len());

                for (_, value, reason) in g.iter() {
                    report.push((reason.clone(), *value));
                }

                report
            },
            Err(g) => panic!("{}", g),
        }
    }

    fn handle_vulnerability(&mut self, vuln: &mut (Condition, bool)) {
        match &mut vuln.0 {
            Condition::FileVuln(d, f) => {
                let pf = File::open(d.clone()).ok();

                match pf {
                    Some(mut file) => vuln.1 = f(self, Some(&mut file)),
                    None => vuln.1 = f(self, None),
                }
            },
            Condition::AppVuln(a, f) => {
                vuln.1 = f(self, a.clone());
            },
            Condition::UserVuln(u, f) => {
                vuln.1 = f(self, u.name.as_str());
            },
            Condition::CustomVuln(f) => {
                vuln.1 = f(self);
            },
        }
    }

    /// Executes vulnerabilites
    ///
    /// Incomplete vulnerabilites are excuted each time the function is executed.
    /// Complete vulnerabilites are excuted only if the number of iterations mod [`complete_freq`][`Engine::set_completed_freq`] is 0
    pub fn update(&mut self) -> () {
        self.in_execution.store(true, Ordering::SeqCst);
        let tmp_vulns = Arc::clone(&self.vulns); 
        
        // Neat trick to get out of immutable borrow complaints
        match tmp_vulns.lock() {
            Ok(mut vulns) => {
                for vuln in vulns.iter_mut() {
                    if self.step_iter.load(Ordering::SeqCst) % self.complete_freq.load(Ordering::SeqCst) == 0 && vuln.1 {
                        self.handle_vulnerability(vuln);
                    } else {
                        self.handle_vulnerability(vuln);
                    }
                }
            },
            Err(g) => panic!("{}",g)
        };

        self.in_execution.store(false, Ordering::SeqCst);
    }

    /// Start engine execution on this thread
    /// 
    /// This enters an loop that calls [`Engine::update`] [`incomplete_freq`][`Engine::set_freq`] times per second.
    /// 
    /// This state of execution only takes control of one thread, and other threads can generally continue without issue,
    /// however, new vulnerabilities cannot be added.
    pub fn enter(&mut self) -> () {

        self.is_running.store(true, Ordering::SeqCst);
        // TODO: init
    
        while self.is_running.load(Ordering::SeqCst) {
            self.update();

            sleep(Duration::from_secs_f32(1.0/(self.incomplete_freq.load(Ordering::SeqCst) as f32)));
        }
    }

    /// Tells the engine to exit.
    /// 
    /// This stops engine execution if [`Engine::enter`] was called.
    /// Otherwise does nothing, unless if `blocking` is set to true.
    /// If `blocking` is set, it will wait until the current running update stops to return.
    pub fn stop(&mut self, blocking: bool) -> () {
        self.is_running.store(false, Ordering::SeqCst);

        while blocking && self.in_execution.load(Ordering::SeqCst) {
            std::hint::spin_loop(); // TODO: Optimize this shit
        }
    }

    /// Calculate a total score
    /// 
    /// Calculate the total score for the current engine.
    pub fn calc_total_score(&self) -> i32 {
        match self.score.lock() {
            Ok(guard) => guard.iter().fold(0, |acc, (_, i, _)| acc + i),
            Err(g) => panic!("{}", g),
        }
    }

    /// Get the entry identified by id, if it exists.
    pub fn get_entry(&self, id: u64) -> Option<(u64, i32, String)> {
        match self.score.lock() {
            Ok(guard) => {
                for i in guard.iter() {
                    if id == i.0 {
                        return Some(i.clone())
                    }
                }

                None
            },
            Err(g) => panic!("{}", g),
        }
    }

    /// Checks if the entry identified by id exists
    pub fn entry_exists(&self, id: u64) -> bool {
        match self.score.lock() {
            Ok(guard) => {
                for i in guard.iter() {
                    if id == i.0 {
                        return true;
                    }
                }

                false
            },
            Err(g) => panic!("{}", g),
        }
    }
}