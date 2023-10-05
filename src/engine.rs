/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use crate::state::{add_vuln, ConditionData, FileData, UserData};
pub use crate::state::{
    AppData,
    AppInstallMethod as InstallMethod,
    enter_engine,
    update_engine,
    stop_engine,
};
use std::{fs::File, string::String, str::FromStr};

/// Register a file based vulnerability
/// 
/// Register a file based vulnerability.
/// This takes the form of a function/closure that takes an `Option<&mut File>` as it's only parameter, and returns a bool.
/// 
/// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
/// More on that in [`engine::update_engine`] and [`engine::enter_engine`]
pub fn add_file_vuln<F>(name: &str, f: F)
where 
    F: FnMut(Option<&mut File>) -> bool + Send + Sync + 'static, // Whiny ass compiler
{
    let fd = FileData {
        name: String::from_str(name).unwrap(),
        position: 0,
    };

    add_vuln(ConditionData::FileVuln(fd, Box::new(f) as Box<dyn FnMut(Option<&mut File>) -> bool + Send + Sync>));
}

/// Register a package/app based vulnerability
/// 
/// Register a package/app based vulnerability.
/// This takes the form of a function/closure that takes an `AppData` as it's only parameter, and returns a bool.
/// 
/// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
/// More on that in [`engine::update_engine`] and [`engine::enter_engine`]
pub fn add_appbased_vuln<F>(name: &str, install_method: InstallMethod, f: F)
where 
    F: FnMut(AppData) -> bool + Send + Sync + 'static, // Whiny ass compiler
{
    let ad = AppData {
        name: String::from_str(name).unwrap(),
        install_method: install_method,
    };

    add_vuln(ConditionData::AppVuln(ad, Box::new(f) as Box<dyn FnMut(AppData) -> bool + Send + Sync>));
}

/// Register a user based vulnerability
/// 
/// Register a user based vulnerability.
/// This takes the form of a function/closure that takes an `&str` as it's only parameter, and returns a bool.
/// 
/// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
/// More on that in [`engine::update_engine`] and [`engine::enter_engine`]
pub fn add_userbased_vuln<F>(name: &str, f: F)
where 
    F: FnMut(&str) -> bool + Send + Sync + 'static, // Whiny ass compiler
{
    let ud = UserData {
        name: String::from_str(name).unwrap(),
    };

    add_vuln(ConditionData::UserVuln(ud, Box::new(f) as Box<dyn FnMut(&str) -> bool + Send + Sync>));
}

/// Register a miscellaneous vulnerability
/// 
/// Register a miscellaneous vulnerability.
/// This takes the form of a function/closure that takes no parameters, and returns a bool.
/// 
/// If the closure returns true, the vulnerability is interpreted as being completed, it is incomplete.
/// More on that in [`engine::update_engine`] and [`engine::enter_engine`]
pub fn add_misc_vuln<F>(f: F)
where
    F: FnMut(()) -> bool + Send + Sync + 'static,
{
    add_vuln(ConditionData::CustomVuln(Box::new(f) as Box<dyn FnMut(()) -> bool + Send + Sync>));
}