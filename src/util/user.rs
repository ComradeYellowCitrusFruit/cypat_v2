/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/
use std::{
	vec::Vec, 
	string::String, 
	fs::File,
	io::{BufRead, BufReader, Read}, 
	str::FromStr,
	process::{Command, Stdio},
};

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub struct GroupEntry {
	pub groupname: String,
	pub gid: u64,
	pub list: Vec<String>,
}

#[cfg(target_os = "linux")]
impl PasswdEntry {
	pub fn parse_entry(entry: &str) -> PasswdEntry {
		let tokenized_entry: Vec<&str> = entry.split(':').collect();
		let entry: PasswdEntry;
		entry.username = tokenized_entry[0];
		entry.password_in_shadow = tokenized_entry[1] == "x";
		entry.uid = tokenized_entry[2].parse::<u64>().unwrap();
		entry.gid = tokenized_entry[3].parse::<u64>().unwrap();
		entry.gecos = String::from_str(tokenized_entry[4]);
		entry.home_dir = String::from_str(tokenized_entry[5]);
		entry.shell = String::from_str(tokenized_entry[6]);
		entry
	}

	pub fn find_and_parse_entry<T>(name: &str, reader: T) -> Option<PasswdEntry>
	where
		T: BufRead + Read
	{
		for i in reader.lines().map(|l| l.ok()) {
			match i {
				Some(s) => {
					if s.split(':').collect::<Vec<_>>()[0] == String::from_str(name).unwrap() {
						return Some(Self::parse_entry(s));
					}
				},
				None => break,
			}
		}

		None
	}
}

pub fn user_exists(name: &str) -> bool {
	#[cfg(target_os = "linux")]
	{
		// not quite what I'd like to do but that's fine
		let reader = BufReader::new(File::open("/etc/passwd"));
		find_and_parse_entry(name, reader).is_none()
	}
	#[cfg(target_os = "windows")]
	{
		let cmd = Command::new("wmic")
        .args(&["useraccount", "where", &format!("Name='{}'", name)])
		.stderr(Stdio::null()).stdout(Stdio::piped()).output();
		match cmd.ok() {
			Some(o) => String::from_utf8_lossy(&o.stdout).contains(name),
			None => false,
		}
	}
}

pub fn user_is_in_group(uname: &str, gname: &str) -> Result<bool, ()> {
	#[cfg(target_os = "linux")]
	{
		let reader = BufReader::new(File::open("/etc/group"));

		for i in reader.lines().map(|l| l.ok()) {
			match i {
				Some(line) => {
                    if line.contains(gname) {
                        return Ok(line.contains(uname));
                    } else {
                        continue;
                    }
                },
				None() => return Err(()),
			}
		}
	}
	#[cfg(target_os = "windows")]
	{
        // TODO: this
        todo!()
	}
}