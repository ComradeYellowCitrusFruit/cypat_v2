/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use lazy_static::lazy_static;
use std::{
    sync::{Mutex, PoisonError, MutexGuard, atomic::AtomicI64},
    fs::File,
    mem::ManuallyDrop,
    collections::BTreeMap,
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

pub(crate) struct FileData {
    pub(crate) name: &'static str,
    pub(crate) position: u64
}

#[derive(Clone, Copy)]
pub struct AppData {
    pub(crate) install_method: AppInstallMethod,
    pub(crate) name: &'static str,
}

#[derive(Clone, Copy)]
pub(crate) struct UserData {
    pub(crate) name: &'static str,
}

pub(crate) enum ConditionData {
    FileVuln(FileData, Box<dyn FnMut(Option<File>) -> () + Send + Sync>),
    AppVuln(AppData, Box<dyn FnMut(AppData) -> () + Send + Sync>),
    UserVuln(UserData, Box<dyn FnMut(&str) -> () + Send + Sync>),
    CustomVuln(Box<dyn FnMut(()) -> () + Send + Sync>),
}

lazy_static! {
    static ref SCORE: Mutex<Vec<(i32, String)>> = Mutex::new(Vec::with_capacity(32));
    static ref VULNS: Mutex<Vec<(ConditionData, bool)>> = Mutex::new(Vec::with_capacity(32));
    static ref START_TIME: Instant = Instant::now();
}

pub fn add_score(add: i32, reason: String) {
    match (*SCORE).lock() {
        Ok(mut g) => (*g).push((add, reason)),
        Err(g) => panic!("{}", g),
    }
}

pub fn sub_score(sub: i32, reason: String) {
    add_score(-sub, reason)
}

pub(crate) fn add_vuln(vuln: ConditionData) {
    match (*VULNS).lock() {
        Ok(mut g) => g.push((vuln, false)),
        Err(g) => panic!("{}", g),
    }
}