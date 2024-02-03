/*
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use std::{mem::MaybeUninit, process::{Command, Stdio}, ptr::null_mut, result::Result};

#[cfg(target_os = "linux")]
use libc::{uid_t, gid_t, stat, getpwnam_r, sysconf, getgrnam_r};

#[cfg(target_os = "windows")]
use winapi::um::{
    fileapi::CreateFileW, 
    winnt::{GENERIC_READ, FILE_ATTRIBUTE_NORMAL, READ_CONTROL}, 
    handleapi::INVALID_HANDLE_VALUE,
    accctrl::SE_OBJECT_TYPE,
    aclapi::GetSecurityInfo
};

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
        let mut h = CreateFileW(fname.encode_utf16().collect::<Vec<_>>().as_ptr(), GENERIC_READ, 1, null_mut(), 3, FILE_ATTRIBUTE_NORMAL, null_mut());
        let mut psid = null_mut();
        let mut nombre = [0u16; 1024];
        let mut tmp = 1024;
        let mut garbage;
        let mut name_use;
        if h == INVALID_HANDLE_VALUE {
            return Err(errno());
        }

        if GetSecurityInfo(h, SE_OBJECT_TYPE::SE_FILE_OBJECT, READ_CONTROL, &mut psid, null_mut(), null_mut(), null_mut()) != 0{
            return Err(errno());
        }

        if LookupAccountSidW(null(), psid, &nombre.as_ptr(), &mut tmp, null_mut(), &mut garbage, &mut name_use) != 0 {
            Ok(String::from_utf16(&nombre) == uname)
        } else {
            Err(errno())
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