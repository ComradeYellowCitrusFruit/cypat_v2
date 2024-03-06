/*
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use std::{
    ptr::{null_mut, null}, 
    result::Result, 
    str::FromStr,
    mem::MaybeUninit,
};

#[cfg(target_os = "linux")]
use std::ffi::CString;

#[cfg(target_os = "linux")]
use libc::{uid_t, gid_t, stat, getpwnam_r, sysconf, getgrnam_r};

#[cfg(target_os = "linux")]
use super::{PasswdEntry, GroupEntry};

#[cfg(target_os = "windows")]
use winapi::um::{
    fileapi::CreateFileW, 
    winnt::{GENERIC_READ, FILE_ATTRIBUTE_NORMAL, READ_CONTROL}, 
    handleapi::{INVALID_HANDLE_VALUE, CloseHandle},
    accctrl::SE_FILE_OBJECT,
    aclapi::GetSecurityInfo,
    winbase::LookupAccountSidW
};

use super::errno;

/// Check if the file named `name` is owned by the user with UID `uid`
#[cfg(target_os = "linux")]
pub fn file_owned_by_uid<T: ToString>(uid: uid_t, name: &T) -> Result<bool, i32> {
    Ok(get_file_owner_uid(name)? == uid)
}

/// Check if the file named `name` is owned by the group with GID `gid`
#[cfg(target_os = "linux")]
pub fn file_owned_by_gid<T: ToString>(gid: gid_t, name: &T) -> Result<bool, i32> {
    Ok(get_file_owner_gid(name)? == gid)
}

/// Check if the file named `fname` is owned by the user named `uname`
pub fn file_owned_by_user<A: ToString, B: ToString>(uname: &A, fname: &B) -> Result<bool, i32> {
    Ok(get_file_owner::<B, String>(fname)? == uname.to_string())
}

/// Check if the file named `fname` is owned by the group named `gname`
#[cfg(target_os = "linux")]
pub fn file_owned_by_group<A: ToString, B: ToString>(g: &A, f: &B) -> Result<bool, i32> {
    Ok(get_file_owner::<B, String>(f)? == g.to_string())
}

#[cfg(target_os = "linux")]
pub fn get_file_owner_uid<T: ToString>(f: &T) -> Result<uid_t, i32> {
    let filename = match CString::new(f.to_string()) {
        Ok(s) => s,
        _ => return Err(-1)
    };

    unsafe {
        let mut s = MaybeUninit::zeroed().assume_init();
        if stat(filename.as_ptr() as *const i8, &mut s) == 0 {
            Ok(s.st_uid)
        } else {
            Err(errno())
        }
    }
}

#[cfg(target_os = "linux")]
pub fn get_file_owner_gid<T: ToString>(f: &T) -> Result<gid_t, i32> {
    let filename = match CString::new(f.to_string()) {
        Ok(s) => s,
        _ => return Err(-1)
    };

    unsafe {
        let mut s = MaybeUninit::zeroed().assume_init();
        if stat(filename.as_ptr() as *const i8, &mut s) == 0 {
            Ok(s.st_gid)
        } else {
            Err(errno())
        }
    }
}

#[cfg(target_os = "linux")]
pub fn get_file_group<A: ToString, B: FromStr>(f: &A) -> Result<B, i32> {
    let uid = get_file_owner_gid(f)?;
    let entry = GroupEntry::get_entry_by_gid(uid)?;
    match B::from_str(entry.groupname.as_str()) {
        Ok(s) => Ok(s),
        _ => Err(-1)
    }
}

pub fn get_file_owner<A: ToString, B: FromStr>(f: &A) -> Result<B, i32> {
    #[cfg(target_os = "linux")]
    {
        let uid = get_file_owner_uid(f)?;
        let entry = PasswdEntry::get_entry_from_passwd_by_uid(uid)?;
        match B::from_str(entry.username.as_str()) {
            Ok(s) => Ok(s),
            _ => Err(-1)
        }
    }
    #[cfg(target_os = "windows")]
    unsafe {
        let h = CreateFileW(
            f.to_string().encode_utf16().collect::<Vec<_>>().as_ptr(), 
            GENERIC_READ, 
            1, 
            null_mut(), 
            3, 
            FILE_ATTRIBUTE_NORMAL, 
            null_mut()
        );

        let mut psid = null_mut();
        let mut nombre = [0u16; 1024];
        let mut tmp = 1024;
        let mut garbage = 0;
        let mut name_use = 0;
        
        if h == INVALID_HANDLE_VALUE {
            return Err(errno());
        }

        if GetSecurityInfo(h, SE_FILE_OBJECT as u32, READ_CONTROL, &mut psid, null_mut(), null_mut(), null_mut(), null_mut()) != 0{
            return Err(errno());
        }

        if CloseHandle(h) == 0 {
            return Err(errno());
        }

        if LookupAccountSidW(null(), psid, nombre.as_mut_ptr(), &mut tmp, null_mut(), &mut garbage, &mut name_use) != 0 {
            let owner: String = String::from_utf16(&nombre).unwrap_or_else(|_| "ñ".into()).chars().filter(|c| *c != '\0').collect();

            match B::from_str(owner.as_str()) {
                Ok(s) => Ok(s),
                _ => Err(-1)
            }
        } else {
            Err(errno())
        }
    }
}