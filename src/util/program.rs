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
use crate::engine::{AppData, InstallMethod};

/// A bool but with three options, [`TripleBool::Known`], [`TripleBool::Unknown`]
#[derive(Copy, Clone)]
pub enum TripleBool {
	Known(bool),
	Unknown,
}

/// Check if a package is installed purely from the name
/// 
/// On Linux, `name` should be the package name, to query package managers for.
/// On Windows, `name` should be the name of the exe file, to query the registry for.
pub fn is_package_installed<T: ToString>(name: &T) -> bool {
	#[cfg(target_os = "linux")]
 	{
		let pkg_name = name.to_string();
		let dpkg_cmd = Command::new("dpkg").args(&["-l"]).stderr(Stdio::null()).stdout(Stdio::piped())
			.output().expect("O no estamos en una distribución basada en Debian o algo está realmente mal.");

		if String::from_utf8_lossy(&dpkg_cmd.stdout).contains(pkg_name.as_str()) {
			return true;
		}

		match Command::new("flatpak").args(&["list"]).stderr(Stdio::null()).stdout(Stdio::piped()).output().ok() {
			Some(output) => {
				if String::from_utf8_lossy(&output.stdout).contains(pkg_name.as_str()) {
					return true;
				}
			},
			None => (),
		}

		match Command::new("snap").args(&["list"]).stderr(Stdio::null()).stdout(Stdio::piped()).output().ok() {
			Some(output) => {
				if String::from_utf8_lossy(&output.stdout).contains(pkg_name.as_str()) {
					return true;
				}
			},
			None => (),
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
	    		if tmp.contains(name.to_string()) {
					true
				} else {
					false
				}
			},
			None => false,
		}
	}
}

impl AppData {
	pub fn new<T: ToString>(name: &T, install_method: InstallMethod) -> Self {
		Self { name: name.to_string(), install_method: install_method }
	}

	/// Checks if a package is installed
	/// 
	/// For WinGet, APT ([`InstallMethod::Default`] on Linux, aka [`InstallMethod::SystemPackageManager`]), [`InstallMethod::Flatpak`], and [`InstallMethod::Snap`] packages, it uses `self.name` to query said package managers. \
	/// For [`InstallMethod::SystemPackageManager`]/[`InstallMethod::Default`] on Windows, this just calls [`is_package_installed`]. \
	/// For anything else, it default returns [`TripleBool::Unknown`]
	pub fn is_installed(&self) -> TripleBool {

		match self.install_method {
			InstallMethod::Default | InstallMethod::SystemPackageManager => {
				#[cfg(target_os = "linux")]
				{
					let dpkg_cmd = Command::new("dpkg").args(&["-l"])
					    .stderr(Stdio::null()).stdout(Stdio::piped())
			            .output().expect("O no estamos en una distribución basada en Debian o algo está muy mal.");

					TripleBool::Known(String::from_utf8_lossy(&dpkg_cmd.stdout).contains(&self.name))
				}
				#[cfg(target_os = "windows")]
				{
					TripleBool::Known(is_package_installed(&self.name))
				}
			},
			#[cfg(target_os = "linux")]
			InstallMethod::Flatpak => {
				match Command::new("flatpak").args(&["list"]).stderr(Stdio::null()).stdout(Stdio::piped()).output().ok() {
					Some(output) => {
						TripleBool::Known(String::from_utf8_lossy(&output.stdout).contains(&self.name))
					},
					None => TripleBool::Unknown,
				}
			},
			#[cfg(target_os = "linux")]
			InstallMethod::Snap => {
				match Command::new("snap").args(&["list"]).stdout(Stdio::piped()).output().ok() {
					Some(output) => {
						TripleBool::Known(String::from_utf8_lossy(&output.stdout).contains(&self.name))
					},
					None => TripleBool::Unknown,
				}
			},
			#[cfg(target_os = "windows")]
			InstallMethod::WinGet => {
				match Command::new("winget").args(&["list", "--name"]).stderr(Stdio::null()).stdout(Stdio::piped()).output().ok() {
					Some(output) => {
						TripleBool::Known(String::from_utf8_lossy(&output.stdout).contains(&self.name))
					},
					None => TripleBool::Unknown,
				}
			}
			_ => TripleBool::Unknown,
		}
	}
}

// TODO: Mucho más