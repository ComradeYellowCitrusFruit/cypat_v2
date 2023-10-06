/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use std::{result::Result, process::{Command, Stdio, ExitStatus}};

#[cfg(target_os = "linux")]
pub fn file_owned_by_uid(uid: u64, name: &str) -> Result<bool, ()> {
    let cmd = Command::new("stat").args(&["-c", "%u", name])
        .stdout(Stdio::piped()).stderr(Stdio::piped()).output().expect("Either something broke or we aren't on GNU/Linux");
    if cmd.status.success() {
        Ok(String::from_utf8_lossy(&cmd.stdout).parse().unwrap_or(!uid) == uid)
    } else {
        Err(())
    }
}

#[cfg(target_os = "linux")]
pub fn file_owned_by_gid(gid: u64, name: &str) -> Result<bool, ()> {
    let cmd = Command::new("stat").args(&["-c", "%g", name])
        .stdout(Stdio::piped()).stderr(Stdio::piped()).output().expect("Either something broke or we aren't on GNU/Linux");
    if cmd.status.success() {
        Ok(String::from_utf8_lossy(&cmd.stdout).parse().unwrap_or(!gid) == gid)
    } else {
        Err(())
    }
}

pub fn filed_owned_by_user(uname: &str, fname: &str) -> Result<bool, ()> {
    #[cfg(target_os = "linux")]
    {
        let cmd = Command::new("stat").args(&["-c", "%U", fname])
            .stdout(Stdio::piped()).stderr(Stdio::piped()).output().expect("Either something broke or we aren't on GNU/Linux");
        if cmd.status.success() {
            Ok(String::from_utf8_lossy(&cmd.stdout) == uname)
        } else {
            Err(())
        }
    }
    #[cfg(target_os = "windows")]
    {
        todo!()
    }
}

pub fn filed_owned_by_group(gname: &str, fname: &str) -> Result<bool, ()> {
    #[cfg(target_os = "linux")]
    {
        let cmd = Command::new("stat").args(&["-c", "%G", fname])
            .stdout(Stdio::piped()).stderr(Stdio::piped()).output().expect("Either something broke or we aren't on GNU/Linux");
        if cmd.status.success() {
            Ok(String::from_utf8_lossy(&cmd.stdout) == gname)
        } else {
            Err(())
        }
    }
    #[cfg(target_os = "windows")]
    {
        todo!()
    }
}