/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/
#![allow(unused_imports)]

use std::{
	fs::File, 
	io::{BufRead, BufReader, Read}, 
	mem::{ManuallyDrop, MaybeUninit}, 
	process::{Command, Stdio}, 
	ptr::{null, null_mut}, 
	str::FromStr, 
	string::String, 
	vec::Vec,
	ffi::CString,
};

use super::errno;

#[cfg(target_os = "linux")]
use libc::{gid_t, uid_t, sysconf, getpwnam_r, getgrnam_r, getgrouplist, strlen};

#[cfg(target_os = "windows")]
use winapi::{
	um::{
		wincred::NERR_BASE,
		lmaccess::{NetUserGetLocalGroups, NetGroupGetInfo, LPLOCALGROUP_USERS_INFO_0}, 
		lmapibuf::NetApiBufferFree
	}, 
	ctypes::c_void
};

/// An entry to the /etc/group file.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct GroupEntry {
	pub groupname: String,
	pub gid: gid_t,
	pub list: Vec<String>,
}

/// An entry to the /etc/passwd file.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct PasswdEntry {
	pub username: String,
    pub password_in_shadow: bool,
    pub uid: uid_t,
	pub gid: gid_t,
    pub gecos: String,
    pub home_dir: String,
    pub shell: String,
}

#[cfg(target_os = "linux")]
impl PasswdEntry {
	/// Parse a passwd entry from a string
	pub fn parse_entry<T: ToString>(entry: &T) -> PasswdEntry {
		let entry_str = entry.to_string();
		let tokenized_entry: Vec<_> = entry_str.split(':').collect();

		PasswdEntry {
			username: tokenized_entry[0].to_string(),
			password_in_shadow: tokenized_entry[1] == "x",
			uid: tokenized_entry[2].parse::<uid_t>().unwrap(),
			gid: tokenized_entry[3].parse::<gid_t>().unwrap(),
			gecos: tokenized_entry[4].to_string(),
			home_dir: tokenized_entry[5].to_string(),
			shell: tokenized_entry[6].to_string(),
		}
	}
	
	pub fn get_entry_from_passwd<T: ToString>(name: &T) -> Result<PasswdEntry, i32> {
		let username = match CString::new(name.to_string()) {
			Ok(s) => s,
			_ => return Err(-1),
		};

		unsafe {
			let mut pass = MaybeUninit::zeroed().assume_init();
        	let mut pass_ptr = MaybeUninit::zeroed().assume_init();
        	let mut buf = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
        	let mut res ;
			let tmp;
        	res = getpwnam_r(username.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);

        	while res != 0 && errno() == libc::ERANGE {
            	let mut nb = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
            	buf.append(&mut nb);
            	res = getpwnam_r(username.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);
        	}

			if res != 0 {
				return Err(errno());
			}

			tmp = pass_ptr.as_mut().unwrap();

			Ok(PasswdEntry {
				username: String::from_raw_parts(tmp.pw_name as *mut u8, libc::strlen(tmp.pw_name), libc::strlen(tmp.pw_name)),
				uid: tmp.pw_uid,
				gid: tmp.pw_gid,
				password_in_shadow: *tmp.pw_passwd == 'x' as i8,
				gecos: String::from_raw_parts(tmp.pw_gecos as *mut u8, libc::strlen(tmp.pw_gecos), libc::strlen(tmp.pw_gecos)),
				home_dir: String::from_raw_parts(tmp.pw_dir as *mut u8, libc::strlen(tmp.pw_dir), libc::strlen(tmp.pw_dir)),
				shell: String::from_raw_parts(tmp.pw_shell as *mut u8, libc::strlen(tmp.pw_shell), libc::strlen(tmp.pw_shell)),
			}.clone())
		}
	}
}

#[cfg(target_os = "linux")]
impl GroupEntry {
	pub fn get_entry_from_group<T: ToString>(name: &T) -> Result<GroupEntry, i32> {
		let groupname = match CString::new(name.to_string()) {
			Ok(s) => s,
			_ => return Err(-1),
		};

		unsafe {
			let mut pass = MaybeUninit::zeroed().assume_init();
        	let mut pass_ptr = MaybeUninit::zeroed().assume_init();
        	let mut buf = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
        	let mut res ;
			let mut ret;
			let tmp;
        	res = getgrnam_r(groupname.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);

        	while res != 0 && errno() == libc::ERANGE {
            	let mut nb = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
            	buf.append(&mut nb);
            	res = getgrnam_r(groupname.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);
        	}

			if res != 0 {
				return Err(errno());
			}

			tmp = pass_ptr.as_mut().unwrap();

			ret = GroupEntry {
				groupname: String::from_raw_parts(tmp.gr_name as *mut u8, libc::strlen(tmp.gr_name), libc::strlen(tmp.gr_name)),
				gid: tmp.gr_gid,
				list: Vec::new(),
			};

			let mut i = 0;
			while tmp.gr_mem.offset(i).read() != null_mut() {
				let tmp_tmp = tmp.gr_mem.offset(i).read() as *mut i8;
				ret.list.push(String::from_raw_parts(tmp_tmp as *mut u8, libc::strlen(tmp_tmp), libc::strlen(tmp_tmp)));
				i += 1;
			}

			Ok(ret.clone())
		}
	}
}

/// Checks if a user with username `name` exists on the system

pub fn user_exists<T: ToString>(n: &T) -> Result<bool, i32> {
	let name = n.to_string();
	#[cfg(target_os = "linux")]
	unsafe {
		let username = match CString::new(name) {
			Ok(s) => s,
			_ => return Err(-1),
		};

		let mut pass = MaybeUninit::zeroed().assume_init();
        let mut pass_ptr = MaybeUninit::zeroed().assume_init();
    	let mut buf = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
    	let mut res ;
    	res = getpwnam_r(username.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);

        while res != 0 && errno() == libc::ERANGE {
        	let mut nb = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
            buf.append(&mut nb);
        	res = getpwnam_r(username.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);
    	}

		if res == 0 {
			Ok(true)
		} else {
			match errno() {
				0 | libc::ENOENT | libc::ESRCH | libc::EBADF | libc::EPERM => Ok(false),
				_ => Err(errno()),
			}
		}
	}
	#[cfg(target_os = "windows")]
	unsafe {
		let mut user: USER_INFO_0 = null_mut();
		let mut uname_utf16 = name.encode_utf16().collect::<Vec<u16>>();

		match NetGroupGetInfo(null, uname_utf16.as_ptr(), 0, &mut group as *mut *mut u8) {
			0 => { NetApiBufferFree(user as *mut c_void); Ok(true) },
			2220 => Ok(false), /* NERR_GroupNotFound */
			_ => Err(errno()),
		}
	}
}

/// Checks if a group named `name` exists on the system
pub fn group_exists<T: ToString>(n: &T) -> Result<bool, i32> {
	let name = n.to_string();
	#[cfg(target_os = "linux")]
	unsafe {
		let groupname = match CString::new(name) {
			Ok(s) => s,
			_ => return Err(-1),
		};

		let mut pass = MaybeUninit::zeroed().assume_init();
        let mut pass_ptr = MaybeUninit::zeroed().assume_init();
    	let mut buf = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
    	let mut res ;
    	res = getgrnam_r(groupname.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);

        while res != 0 && errno() == libc::ERANGE {
        	let mut nb = vec![0i8; sysconf(libc::_SC_GETPW_R_SIZE_MAX) as usize];
            buf.append(&mut nb);
        	res = getgrnam_r(groupname.as_ptr() as *const i8, &mut pass, buf.as_mut_ptr(), buf.len(), &mut pass_ptr);
    	}

		if res == 0 {
			Ok(true)
		} else {
			match errno() {
				0 | libc::ENOENT | libc::ESRCH | libc::EBADF | libc::EPERM => Ok(false),
				_ => Err(errno()),
			}
		}
	}
	#[cfg(target_os = "windows")]
	unsafe {
		let mut group: GROUP_INFO_0 = null_mut();
		let mut gname_utf16 = name.encode_utf16().collect::<Vec<u16>>();

		match NetGroupGetInfo(null, gname_utf16.as_ptr(), 0, &mut group as *mut *mut u8) {
			0 => { NetApiBufferFree(group as *mut c_void); Ok(true) },
			2220 => Ok(false),
			_ => Err(errno()),
		}
	}
}

/// Checks if a user named `uname` is in the group named `gname`.
/// 
/// If it returns an [`Ok`] value, the both the user and group exist, and the payload contains if the user is in the group.
/// If it returns an [`Err`] value, either the user or group doesn't exist
pub fn user_is_in_group<A: ToString, B: ToString>(u: &A, g: &B) -> Result<bool, i32> {
	user_exists(u)?;
	group_exists(g)?;
	#[cfg(target_os = "linux")]
	{
		let group = GroupEntry::get_entry_from_group(g)?;
		Ok(group.list.contains(&g.to_string()))
	}
	#[cfg(target_os = "windows")]
	{
		let uname = u.to_string();
		let gname = g.to_string();
		let mut groups: LPLOCALGROUP_USERS_INFO_0 = null_mut();
		let mut uname_utf16 = uname.encode_utf16().collect::<Vec<u16>>();
		let mut gname_utf16 = gname.encode_utf16().collect::<Vec<u16>>();
		let mut num_entries = 0;
		let mut tmp = 0;
		uname_utf16.push(0);
		gname_utf16.push(0);

		let status = unsafe {
			NetUserGetLocalGroups(null(), uname_utf16.as_ptr(), 0, 1, &mut groups as *mut *mut u8, u32::MAX, &mut entries, &mut tmp)
		};
		let entries = ManuallyDrop::new(Vec::from_raw_parts(groups, num_entries, num_entries));

		if status == 0 {
			let mut strlen = 0;
			for c in gname_utf16.iter() {
				if(*c == 0) {
					break;
				}
				strlen += 1;
			}

			'groups: for raw_entry in (*entries).iter() {
				let mut i = 0;
				unsafe { 
					while *raw_entry.lgrui0_name.offset(i) != 0 {
						i += 1;
					}
				}

				let entry = ManuallyDrop::new(Vec::from_raw_parts(raw_entry.lgrui0_name, i, i));
				if i != strlen {
					continue;
				}

				for j in 0..i {
					if (*entry)[j] != gname_utf16[j] {
						continue 'groups;
					}
				}

				unsafe { NetApiBufferFree(groups as *mut c_void); }
				return true;
			}

			unsafe { NetApiBufferFree(groups as *mut c_void); }
			return false;
		}
	}
}

/// Checks if the user has administrator privileges. 
/// 
/// On Linux, it checks if the user is either root, or if they have access to sudo.
/// On Windows, it checks if the user is a member of the Administrators group.
/// 
/// If it returns an [`Ok`] value, the user exists and the payload contians if the user has admin privileges
/// If it returns an [`Err`] value, the user does not exist
pub fn user_is_admin<T: ToString>(name: &T) -> Result<bool, ()> {

    #[cfg(target_os = "linux")]
    {
        if name.to_string() == "root" {
            Ok(true)
        } else {
            if user_exists(name).unwrap_or(false) {
                let cmd = Command::new("sudo")
                    .args(&["-l", "-U", &format!("{}", name.to_string())]).stderr(Stdio::null()).stdout(Stdio::piped())
		            .output().expect("¿Por qué sudo no está trabajando?");
                let mensaje = format!("User {} is not allowed to run sudo", name.to_string());

                Ok(!String::from_utf8_lossy(&cmd.stdout).contains(&mensaje))
            } else {
                Err(())
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        user_is_in_group(name, "Administrators")
    }
}