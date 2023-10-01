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
};
use std::{fs::File, string::String, str::FromStr};

pub fn add_file_vuln<F>(name: &str, f: F)
where 
    F: FnMut(Option<&File>) -> bool + Send + Sync + 'static, // Whiny ass compiler
{
    let fd = FileData {
        name: String::from_str(name).unwrap(),
        position: 0,
    };

    add_vuln(ConditionData::FileVuln(fd, Box::new(f) as Box<dyn FnMut(Option<&File>) -> bool + Send + Sync>));
}

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

pub fn add_userbased_vuln<F>(name: &str, f: F)
where 
    F: FnMut(&str) -> bool + Send + Sync + 'static, // Whiny ass compiler
{
    let ud = UserData {
        name: String::from_str(name).unwrap(),
    };

    add_vuln(ConditionData::UserVuln(ud, Box::new(f) as Box<dyn FnMut(&str) -> bool + Send + Sync>));
}

pub fn add_misc_vuln<F>(f: F)
where
    F: FnMut(()) -> bool + Send + Sync + 'static,
{
    add_vuln(ConditionData::CustomVuln(Box::new(f) as Box<dyn FnMut(()) -> bool + Send + Sync>));
}