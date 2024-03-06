/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use std::{
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc, Mutex},
    fs::File,
    io::{Seek, SeekFrom},
    time::Duration,
    thread::sleep,
    str::FromStr,
    string::String,
};

/// Contains package install method.
#[derive(Clone, Copy)]
pub enum InstallMethod {
    Default,
    SystemPackageManager,
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
    FileVuln(String, Box<dyn FnMut(Option<&mut File>) -> bool + Send + Sync>),
    AppVuln(AppData, Box<dyn FnMut(AppData) -> bool + Send + Sync>),
    UserVuln(UserData, Box<dyn FnMut(&str) -> bool + Send + Sync>),
    CustomVuln(Box<dyn FnMut(()) -> bool + Send + Sync>),
}

pub struct Engine {
    is_running: AtomicBool,
    score: Mutex<Vec<(u64, i32, String)>>,
    vulns: Mutex<Vec<(Condition, bool)>>,
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
            score: Mutex::new(Vec::new()),
            vulns: Mutex::new(Vec::new()),
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
    /// This takes the form of a function/closure that takes an [`Option<&mut File>`] as it's only parameter, and returns a [`bool`].
    /// 
    /// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
    /// More on that in [`Engine::update`] and [`Engine::enter`]
    pub fn add_file_vuln<F, S>(&mut self, name: S, f: F)
    where 
        F: FnMut(Option<&mut File>) -> bool + Send + Sync + 'static, // Whiny ass compiler
        S: ToString,
    {
        self.add_vuln(Condition::FileVuln(name.to_string(), Box::new(f) as Box<dyn FnMut(Option<&mut File>) -> bool + Send + Sync>));
    }

    /// Register a package/app vulnerability
    /// 
    /// Register a package/app vulnerability.
    /// This takes the form of a function/closure that takes an [`AppData`] as it's only parameter, and returns a [`bool`].
    /// 
    /// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
    /// More on that in [`Engine::update`] and [`Engine::enter`]    
    pub fn add_app_vuln<F, S>(&mut self, name: S, install_method: InstallMethod, f: F)
    where 
        F: FnMut(AppData) -> bool + Send + Sync + 'static, // Whiny ass compiler
        S: ToString,
    {
        let ad = AppData {
            name: name.to_string(),
            install_method: install_method,
        };

        self.add_vuln(Condition::AppVuln(ad, Box::new(f) as Box<dyn FnMut(AppData) -> bool + Send + Sync>));
    }

    /// Register a user vulnerability
    /// 
    /// Register a user vulnerability.
    /// This takes the form of a function/closure that takes an [`str`] as it's only parameter, and returns a [`bool`].
    /// 
    /// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
    /// More on that in [`Engine::update`] and [`Engine::enter`]
    pub fn add_user_vuln<F, S>(&mut self, name: S, f: F)
    where 
        F: FnMut(&str) -> bool + Send + Sync + 'static, // Whiny ass compiler
        S: ToString,
    {
        let ud = UserData {
            name: name.to_string(),
        };

        self.add_vuln(Condition::UserVuln(ud, Box::new(f) as Box<dyn FnMut(&str) -> bool + Send + Sync>));
    }

    /// Register a miscellaneous vulnerability
    /// 
    /// Register a miscellaneous vulnerability.
    /// This takes the form of a function/closure that takes no parameters, and returns a [`bool`].
    /// 
    /// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
    /// More on that in [`Engine::update`] and [`Engine::enter`]
    pub fn add_misc_vuln<F>(&mut self, f: F)
    where
        F: FnMut(()) -> bool + Send + Sync + 'static,
    {
        self.add_vuln(Condition::CustomVuln(Box::new(f) as Box<dyn FnMut(()) -> bool + Send + Sync>));
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

    fn handle_vulnerability(vuln: &mut (Condition, bool)) {
        match &mut vuln.0 {
            Condition::FileVuln(d, f) => {
                let pf = File::open(d.clone()).ok();

                match pf {
                    Some(mut file) => vuln.1 = f(Some(&mut file)),
                    None => vuln.1 = f(None),
                }
            },
            Condition::AppVuln(a, f) => {
                vuln.1 = f(a.clone());
            },
            Condition::UserVuln(u, f) => {
                vuln.1 = f(u.name.as_str());
            },
            Condition::CustomVuln(f) => {
                vuln.1 = f(());
            },
        }
    }

    /// Executes vulnerabilites
    ///
    /// Incomplete vulnerabilites are excuted each time the function is executed.
    /// Complete vulnerabilites are excuted only if the number of iterations mod [`complete_freq`][`Engine::set_completed_freq`] is 0
    pub fn update(&mut self) -> () {
        self.in_execution.store(true, Ordering::SeqCst);
        match self.vulns.lock() {
            Ok(mut g) => {
                for vuln in (*g).iter_mut() {
                    if self.step_iter.load(Ordering::SeqCst) % self.complete_freq.load(Ordering::SeqCst) == 0 && vuln.1 {
                        Self::handle_vulnerability(vuln);
                    } else {
                        Self::handle_vulnerability(vuln);
                    }
                }
            },
            Err(g) => panic!("{}",g)
        }
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