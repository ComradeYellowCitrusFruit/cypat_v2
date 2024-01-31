/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use std::{
    sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc, Mutex},
    fs::File,
    io::{Seek, SeekFrom},
    time::{Instant, Duration},
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

#[derive(Clone)]
pub(crate) struct FileData {
    pub(crate) name: String,
    pub(crate) position: u64
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
    FileVuln(FileData, Box<dyn FnMut(Option<&mut File>) -> bool + Send + Sync>),
    AppVuln(AppData, Box<dyn FnMut(AppData) -> bool + Send + Sync>),
    UserVuln(UserData, Box<dyn FnMut(&str) -> bool + Send + Sync>),
    CustomVuln(Box<dyn FnMut(()) -> bool + Send + Sync>),
}

pub struct Engine {
    is_running: AtomicBool,
    score: Arc<Mutex<Vec<(u64, i32, String)>>>,
    vulns: Arc<Mutex<Vec<(Condition, bool)>>>,
    incomplete_freq: AtomicU64,
    complete_freq: AtomicU64,
    in_execution: AtomicBool,
}

impl Engine {
    pub fn new() -> Engine {
        Engine {
            is_running: AtomicBool::new(false),
            score: Arc::new(Mutex::new(Vec::new())),
            vulns: Arc::new(Mutex::new(Vec::new())),
            incomplete_freq: AtomicU64::new(5),
            complete_freq: AtomicU64::new(10),
            in_execution: AtomicBool::new(false),
        }
    }

    pub(crate) fn add_vuln(&mut self, vuln: Condition) {
        match (*self.vulns).lock() {
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
    pub fn add_file_vuln<F>(&mut self, name: &str, f: F)
    where 
        F: FnMut(Option<&mut File>) -> bool + Send + Sync + 'static, // Whiny ass compiler
    {
        let fd = FileData {
            name: String::from_str(name).unwrap(),
            position: 0,
        };

        self.add_vuln(Condition::FileVuln(fd, Box::new(f) as Box<dyn FnMut(Option<&mut File>) -> bool + Send + Sync>));
    }

    /// Register a package/app vulnerability
    /// 
    /// Register a package/app vulnerability.
    /// This takes the form of a function/closure that takes an [`AppData`] as it's only parameter, and returns a [`bool`].
    /// 
    /// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
    /// More on that in [`Engine::update`] and [`Engine::enter`]    
    pub fn add_app_vuln<F>(&mut self, name: &str, install_method: InstallMethod, f: F)
    where 
        F: FnMut(AppData) -> bool + Send + Sync + 'static, // Whiny ass compiler
    {
        let ad = AppData {
            name: String::from_str(name).unwrap(),
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
    pub fn add_user_vuln<F>(&mut self, name: &str, f: F)
    where 
        F: FnMut(&str) -> bool + Send + Sync + 'static, // Whiny ass compiler
    {
        let ud = UserData {
            name: String::from_str(name).unwrap(),
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
    pub fn add_score(&mut self, id: u64, add: i32, reason: String) {
        match self.score.lock() {
            Ok(mut g) => (*g).push((id, add, reason)),
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
                let pf = File::open(d.name.clone()).ok();

                match pf {
                    Some(mut file) => {
                        let _ = file.seek(SeekFrom::Start(d.position));
                        vuln.1 = f(Some(&mut file));
                        d.position = file.stream_position().unwrap();
                    },
                    None => {
                        vuln.1 = f(None);
                 },
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
    /// Complete vulnerabilites are excuted only if `iter` mod [`complete_freq`][`Engine::set_completed_freq`] is 0
    pub fn update(&mut self, iter: u64) -> () {
        self.in_execution.store(true, Ordering::SeqCst);
        match self.vulns.lock() {
            Ok(mut g) => {
                for vuln in (*g).iter_mut() {
                    if iter % self.complete_freq.load(Ordering::SeqCst) == 0 && vuln.1 {
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
    /// The value of `cur_iter` passed to [`Engine::update`] is a variable incremented every time the loop is executed
    /// 
    /// This state of execution only takes control of one thread, and other threads can generally continue without issue,
    /// however new vulnerabilities cannot be added.
    pub fn enter(&mut self) -> () {
        let mut iterations = 0;

        self.is_running.store(true, Ordering::SeqCst);
        // TODO: init
    
        while self.is_running.load(Ordering::SeqCst) {
            self.update(iterations);
            iterations += 1;

            sleep(Duration::from_secs_f32(1.0/(self.incomplete_freq.load(Ordering::SeqCst) as f32)));
        }
    }

    /// Tells the engine to exit.
    /// 
    /// This stops engine execution if [`Engine::enter`] was called.
    /// Otherwise does nothing.
    /// If `blocking` is set, it will wait until the current running update stops to return.
    pub fn stop_engine(&mut self, blocking: bool) -> () {
        self.is_running.store(false, Ordering::SeqCst);
    }
}