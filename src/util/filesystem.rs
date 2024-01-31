/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use std::{result::Result, process::{Command, Stdio}, mem::MaybeUninit};

#[cfg(target_os = "linux")]
use libc::{uid_t, gid_t, stat, getpwnam_r, sysconf, getgrnam_r};

use super::errno;

/// Check if the file named `name` is owned by the user with UID `uid`
#[cfg(target_os = "linux")]
pub fn file_owned_by_uid(uid: uid_t, name: &str) -> Result<bool, i32> {
    unsafe {
        let mut s = MaybeUninit::zeroed().assume_init();
        if stat(name.as_ptr() as *const i8, &mut s) == 0 {
            Ok(s.st_uid == uid)
        } else {
            Err(errno())
        }
    }
}

/// Check if the file named `name` is owned by the group with GID `gid`
#[cfg(target_os = "linux")]
pub fn file_owned_by_gid(gid: gid_t, name: &str) -> Result<bool, i32> {
    unsafe {
        let mut s = MaybeUninit::zeroed().assume_init();
        if stat(name.as_ptr() as *const i8, &mut s) == 0 {
            Ok(s.st_gid == gid)
        } else {
            Err(errno())
        }
    }
}

/// Check if the file named `fname` is owned by the user named `uname`
pub fn file_owned_by_user(uname: &str, fname: &str) -> Result<bool, i32> {
    #[cfg(target_os = "linux")]

    unsafe {
        let mut pass = MaybeUninit::zeroed().assume_init();
        let mut pass_ptr = MaybeUninit::zeroed().assume_init();
        let mut buf = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
        let mut res ;
        res = getpwnam_r(uname.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);

        while res != 0 && errno() == libc::ERANGE {
            let mut nb = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
            buf.append(&mut nb);
            res = getpwnam_r(uname.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);
        }

        if res != 0 {
            Err(errno())
        } else {
            file_owned_by_uid(pass_ptr.as_mut().unwrap().pw_uid, fname)
        }
    }
    #[cfg(target_os = "windows")]
    {
        let cmd = Command::new("dir").args(&["/q", fname])
            .stdout(Stdio::piped()).stderr(Stdio::piped()).output().expect("What kind of Windows is this?");
        if cmd.status.success() {
            Ok(String::from_utf8_lossy(&cmd.stdout).contains(uname))
        } else {
            Err(())
        }
    }
}

/// Check if the file named `fname` is owned by the group named `gname`
#[cfg(target_os = "linux")]
pub fn file_owned_by_group(gname: &str, fname: &str) -> Result<bool, i32> {
    unsafe {
        let mut pass = MaybeUninit::zeroed().assume_init();
        let mut pass_ptr = MaybeUninit::zeroed().assume_init();
        let mut buf = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
        let mut res ;
        res = getgrnam_r(gname.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);

        while res != 0 && errno() == libc::ERANGE {
            let mut nb = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
            buf.append(&mut nb);
            res = getgrnam_r(gname.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);
        }

        if res != 0 {
            Err(errno())
        } else {
            file_owned_by_uid(pass_ptr.as_mut().unwrap().gr_gid, fname)
        }
    }
}