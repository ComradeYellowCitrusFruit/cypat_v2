/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use crate::state::{add_vuln, Condition, FileData, UserData};
pub use crate::state::{
    AppData,
    AppInstallMethod as InstallMethod,
    enter_engine,
    update_engine,
    stop_engine,
};
use std::{
    fs::File, 
    str::FromStr, 
    string::String, 
    sync::{atomic::{AtomicBool, AtomicU64}, Arc, Mutex}, 
    time::Instant
};

pub struct Engine {
    is_running: AtomicBool,
    score: Arc<Mutex<Vec<(u64, i32, String)>>>,
    vulns: Arc<Mutex<Vec<(Condition, bool)>>>,
    start_time: Instant,
    incomplete_freq: AtomicU64,
    complete_freq: AtomicU64,
}

impl Engine {
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
    /// More on that in [`update_engine`] and [`enter_engine`]
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
    /// More on that in [`update_engine`] and [`enter_engine`]    
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
    /// More on that in [`update_engine`] and [`enter_engine`]
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
    /// More on that in [`update_engine`] and [`enter_engine`]
    pub fn add_misc_vuln<F>(&mut self, f: F)
    where
        F: FnMut(()) -> bool + Send + Sync + 'static,
    {
        self.add_vuln(Condition::CustomVuln(Box::new(f) as Box<dyn FnMut(()) -> bool + Send + Sync>));
    }
}