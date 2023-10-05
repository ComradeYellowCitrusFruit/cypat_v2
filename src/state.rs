/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use lazy_static::lazy_static;
use std::{
    sync::{Mutex, atomic::{AtomicU64, Ordering, AtomicBool}},
    fs::File,
    time::{Instant, Duration},
    io::{SeekFrom, Seek},
    thread::sleep,
};

/// Contains package install information.
#[derive(Clone, Copy)]
pub enum AppInstallMethod {
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
    pub install_method: AppInstallMethod,
    pub name: String,
}

#[derive(Clone)]
pub(crate) struct UserData {
    pub(crate) name: String,
}

pub(crate) enum ConditionData {
    FileVuln(FileData, Box<dyn FnMut(Option<&mut File>) -> bool + Send + Sync>),
    AppVuln(AppData, Box<dyn FnMut(AppData) -> bool + Send + Sync>),
    UserVuln(UserData, Box<dyn FnMut(&str) -> bool + Send + Sync>),
    CustomVuln(Box<dyn FnMut(()) -> bool + Send + Sync>),
}

lazy_static! {
    static ref SCORE: Mutex<Vec<(u64, i32, String)>> = Mutex::new(Vec::with_capacity(32));
    static ref VULNS: Mutex<Vec<(ConditionData, bool)>> = Mutex::new(Vec::with_capacity(32));
    static ref START_TIME: Instant = Instant::now();
    static ref INCOMPLETE_FREQ: AtomicU64 = AtomicU64::new(1);
    static ref COMPLETE_FREQ: AtomicU64 = AtomicU64::new(5);
    static ref ENGINE_IS_RUNNING: AtomicBool = AtomicBool::new(true);
}

/// Adds an entry to the score report, with an ID, a score value, and an explanation
pub fn add_score(id: u64, add: i32, reason: String) {
    match (*SCORE).lock() {
        Ok(mut g) => (*g).push((id, add, reason)),
        Err(g) => panic!("{}", g),
    }
}

/// Removes the entry identifed
pub fn remove_score(id: u64) -> Result<(), ()> {
    match (*SCORE).lock() {
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
/// Generates a vector containing the explaination and value of each score entry in order
pub fn generate_score_report() -> Vec<(String, i32)> {
    match (*SCORE).lock() {
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

/// Sets the frequency in seconds at which the engine is updated.
/// 
/// Sets the frequency in seconds at which [`update_engine`] is called, if using [`enter_engine`].
/// 
/// Internally this is handled as a variable called `INCOMPLETE_UPDATE_FREQ`
pub fn set_update_freq(frequency: u64) {
    (*INCOMPLETE_FREQ).store(frequency, Ordering::SeqCst);
}

/// Sets the frequency in iterations of engine updates that completed vulnerabilities are reviewed.
/// 
/// Sets the frequency in iterations of engine updates that completed vulnerabilities are re-executed.
/// This value is important even if you don't use [`enter_engine`] because of the way it is interpreted by [`update_engine`]
/// 
/// Internally this is handled as a variable called `COMPLETE_UPDATE_FREQ`
pub fn set_completed_update_freq(frequency: u64) {
    (*COMPLETE_FREQ).store(frequency, Ordering::SeqCst);
}

pub(crate) fn add_vuln(vuln: ConditionData) {
    match (*VULNS).lock() {
        Ok(mut g) => g.push((vuln, false)),
        Err(g) => panic!("{}", g),
    }
}

fn handle_vulnerability(vuln: &mut (ConditionData, bool)) {
    match &mut vuln.0 {
        ConditionData::FileVuln(d, f) => {
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
        ConditionData::AppVuln(a, f) => {
            vuln.1 = f(a.clone());
        },
        ConditionData::UserVuln(u, f) => {
            vuln.1 = f(u.name.as_str());
        },
        ConditionData::CustomVuln(f) => {
            vuln.1 = f(());
        },
    }
}

/// Executes vulnerabilites
/// 
/// Incomplete vulnerabilites are excuted each time the function is executed.
/// Complete vulnerabilites are excuted only if `cur_iter` mod `COMPLETE_UPDATE_FREQ` is 0
pub fn update_engine(cur_iter: u64) -> () {
    match (*VULNS).lock() {
        Ok(mut g) => {
            for vuln in (*g).iter_mut() {
                if cur_iter % (*COMPLETE_FREQ).load(Ordering::SeqCst) == 0 && vuln.1 {
                    handle_vulnerability(vuln);
                } else {
                    handle_vulnerability(vuln);
                }
            }
        },
        Err(g) => panic!("{}",g)
    }
}

/// Start engine execution on this thread
/// 
/// This enters an loop that calls [`update_engine`], 
/// and then sleeps for `INCOMPLETE_UPDATE_FREQ` (see [`set_update_freq`]) seconds.
/// The value of `cur_iter` passed to [`update_engine`] is a variable incremented every time the loop is executed
/// 
/// This state of execution only takes control of one thread, and other threads can generally continue without issue,
/// however new vulnerabilities cannot be added.
pub fn enter_engine() -> () {
    let mut iterations = 0;

    (*ENGINE_IS_RUNNING).store(true, Ordering::SeqCst);
    // TODO: init
    
    while (*ENGINE_IS_RUNNING).load(Ordering::SeqCst) {
        update_engine(iterations);
        iterations += 1;

        sleep(Duration::from_secs((*INCOMPLETE_FREQ).load(Ordering::SeqCst)));
    }
}

/// Tells the engine to exit.
/// 
/// This stops engine execution if [`enter_engine()`] was called.
/// Otherwise does nothing
pub fn stop_engine() -> () {
    (*ENGINE_IS_RUNNING).store(false, Ordering::SeqCst)
}