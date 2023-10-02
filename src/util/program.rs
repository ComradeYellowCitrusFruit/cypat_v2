/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/
#![allow(unused_imports)]

use std::{
	fs::File,
	process::{Command, Stdio},
};

pub fn is_package_installed(name: &str) -> bool {
	#[cfg(target_os = "linux")]
	{
		let dpkg_cmd = Command::new("dpkg").args(&["-l"]).stderr(Stdio::null()).stdout(Stdio::piped())
			.output().expect("O no estamos en una distribución basada en Debian o algo está realmente mal.");

		if String::from_utf8_lossy(&dpkg_cmd.stdout).contains(name) {
			return true;
		}

		match Command::new("flatpak").args(&["list"]).stderr(Stdio::null()).stdout(Stdio::piped()).output().ok() {
			Some(output) => {
				if String::from_utf8_lossy(&output.stdout).contains(name) {
					return true;
				}
			},
			None() => (),
		}

		match Command::new("snap").args(&["list"]).stderr(Stdio::null()).stdout(Stdio::piped()).output().ok() {
			Some(output) => {
				if String::from_utf8_lossy(&output.stdout).contains(name) {
					return true;
				}
			},
			None() => (),
		}

		false
	}
	#[cfg(target_os = "windows")]
	{
		let cmd = Command::new("reg")
        .args(&["query", "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths", "-s"])
		.stderr(Stdio::null()).stdout(Stdio::piped()).output();
		match cmd.ok() {
			Some(o) => {
				let tmp = String::from_utf8_lossy(&o.stdout);
	    		if tmp.contains(name) {
					true
				} else {
					false
				}
			},
			None => false,
		}
	}
}

// TODO: Mucho más