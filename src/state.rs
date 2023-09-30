/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use lazy_static::lazy_static;
use std::{
    sync::Mutex,
    fs::File,
    time::Instant,
};

#[derive(Clone, Copy)]
pub enum AppInstallMethod {
    Default,
    SystemPackageManager,
    WinGet,
    Snap,
    Flatpak,
    ManualInstall,
}

#[derive(Clone)]
pub(crate) struct FileData {
    pub(crate) name: String,
    pub(crate) position: u64
}

#[derive(Clone)]
pub struct AppData {
    pub(crate) install_method: AppInstallMethod,
    pub(crate) name: String,
}

#[derive(Clone)]
pub(crate) struct UserData {
    pub(crate) name: String,
}

pub(crate) enum ConditionData {
    FileVuln(FileData, Box<dyn FnMut(Option<File>) -> bool + Send + Sync>),
    AppVuln(AppData, Box<dyn FnMut(AppData) -> bool + Send + Sync>),
    UserVuln(UserData, Box<dyn FnMut(&str) -> bool + Send + Sync>),
    CustomVuln(Box<dyn FnMut(()) -> bool + Send + Sync>),
}

lazy_static! {
    static ref SCORE: Mutex<Vec<(u64, i32, String)>> = Mutex::new(Vec::with_capacity(32));
    static ref VULNS: Mutex<Vec<(ConditionData, bool)>> = Mutex::new(Vec::with_capacity(32));
    static ref START_TIME: Instant = Instant::now();
}

pub fn add_score(id: u64, add: i32, reason: String) {
    match (*SCORE).lock() {
        Ok(mut g) => (*g).push((id, add, reason)),
        Err(g) => panic!("{}", g),
    }
}

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

pub(crate) fn add_vuln(vuln: ConditionData) {
    match (*VULNS).lock() {
        Ok(mut g) => g.push((vuln, false)),
        Err(g) => panic!("{}", g),
    }
}

#[cfg(RUSTC_IS_NIGHTLY)]
#[feature(never_type)]
pub fn enter_engine() -> ! {
    let mut iterations = 0;
    // TODO: init

    loop {

    }
}

#[cfg(not(RUSTC_IS_NIGHTLY))]
pub fn enter_engine() -> () {
    let mut iterations = 0;
    // TODO: init
    
    loop {
        match (*VULNS).lock() {
            Ok(mut g) => {
                for vuln in (*g).iter_mut() {
                    if iterations % 5 == 0 && vuln.1 {
                        match vuln.0 {
                            _ => todo!(),
                        }
                    }
                }
            },
            Err(g) => panic!("{}",g)
        }
    }
}