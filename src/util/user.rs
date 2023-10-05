/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/
#![allow(unused_imports)]

use std::{
	vec::Vec, 
	string::String, 
	fs::File,
	io::{BufRead, BufReader, Read}, 
	str::FromStr,
	process::{Command, Stdio},
};

/// An entry to the /etc/group file.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct GroupEntry {
	pub groupname: String,
	pub gid: u64,
	pub list: Vec<String>,
}

/// An entry to the /etc/passwd file.
#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct PasswdEntry {
	pub username: String,
    pub password_in_shadow: bool,
    pub uid: u64,
	pub gid: u64,
    pub gecos: String,
    pub home_dir: String,
    pub shell: String,
}

#[cfg(target_os = "linux")]
impl PasswdEntry {
	/// Parse a passwd entry from a string
	pub fn parse_entry(entry: &str) -> PasswdEntry {
		let tokenized_entry: Vec<&str> = entry.split(':').collect();

		PasswdEntry {
			username: tokenized_entry[0].to_string(),
			password_in_shadow: tokenized_entry[1] == "x",
			uid: tokenized_entry[2].parse::<u64>().unwrap(),
			gid: tokenized_entry[3].parse::<u64>().unwrap(),
			gecos: tokenized_entry[4].to_string(),
			home_dir: tokenized_entry[5].to_string(),
			shell: tokenized_entry[6].to_string(),
		}
	}

	/// Try to find and parse an entry with username `name` in `reader`
	pub fn find_and_parse_entry<T>(name: &str, reader: T) -> Option<PasswdEntry>
	where
		T: BufRead + Read
	{
		for i in reader.lines().map(|l| l.ok()) {
			match i {
				Some(s) => {
					if s.split(':').collect::<Vec<_>>()[0] == String::from_str(name).unwrap() {
						return Some(Self::parse_entry(&s));
					}
				},
				None => break,
			}
		}

		None
	}
}

/// Checks if a user with username `name` exists on the system
pub fn user_exists(name: &str) -> bool {
	#[cfg(target_os = "linux")]
	{
		// not quite what I'd like to do but that's fine
		let reader = BufReader::new(File::open("/etc/passwd").expect("Geniunely what the fuck?"));
		PasswdEntry::find_and_parse_entry(name, reader).is_some()
	}
	#[cfg(target_os = "windows")]
	{
		let cmd = Command::new("net")
        .args(&["user", &format!("{}", name)])
		.stderr(Stdio::null()).stdout(Stdio::piped()).output();
		match cmd.ok() {
			Some(o) => String::from_utf8_lossy(&o.stdout).contains(name),
			None => false,
		}
	}
}

/// Checks if a group named `name` exists on the system
pub fn group_exists(name: &str) -> bool {
	#[cfg(target_os = "linux")]
	{
		let reader = BufReader::new(File::open("/etc/group").expect("Geniunely what the fuck?"));

		for i in reader.lines().map(|l| l.ok()) {
			match i {
				Some(line) => {
                    if line.contains(name) {
                        return true;
                    } else {
                        continue;
                    }
                },
				None => return false,
			}
		}

		false
	}
	#[cfg(target_os = "windows")]
	{
		let cmd = Command::new("net")
        .args(&["localgroup", &format!("{}", name)])
		.stderr(Stdio::null()).stdout(Stdio::piped()).output();
		match cmd.ok() {
			Some(o) => String::from_utf8_lossy(&o.stdout).contains(name),
			None => false,
		}
	}
}

/// Checks if a user named `uname` is in the group named `gname`.
/// 
/// If it returns an [`Ok`] value, the both the user and group exist, and the payload contains if the user is in the group.
/// If it returns an [`Err`] value, either the user or group doesn't exist
pub fn user_is_in_group(uname: &str, gname: &str) -> Result<bool, ()> {
	#[cfg(target_os = "linux")]
	{
		let reader = BufReader::new(File::open("/etc/group").expect("Genuinely what the fuck?"));

		for i in reader.lines().map(|l| l.ok()) {
			match i {
				Some(line) => {
                    if line.contains(gname) {
                        return Ok(line.contains(uname));
                    } else {
                        continue;
                    }
                },
				None => return Err(()),
			}
		}
		
		Err(())
	}
	#[cfg(target_os = "windows")]
	{
        let cmd = Command::new("net")
        .args(&["localgroup", &format!("{}", gname)])
		.stderr(Stdio::null()).stdout(Stdio::piped()).output();
		match cmd.ok() {
			Some(o) => {
				let tmp = String::from_utf8_lossy(&o.stdout);
                
	    		if tmp.contains(gname) {
					Ok(tmp.contains(uname))
				} else {
					Err(())
				}
			},
			None => Err(()),
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
pub fn user_is_admin(name: &str) -> Result<bool, ()> {
    #[cfg(target_os = "linux")]
    {
        if name == "root" {
            Ok(true)
        } else {
            if user_exists(name) {
                let cmd = Command::new("net")
                    .args(&["-l", "-U", &format!("{}", name)]).stderr(Stdio::null()).stdout(Stdio::piped())
		            .output().expect("¿Por qué sudo no esta trabajando?");
                let mensaje = format!("User {} is not allowed to run sudo", name);

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