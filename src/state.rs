/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/

use lazy_static::lazy_static;
use std::sync::{Mutex, PoisonError, MutexGuard};

lazy_static! {
    static ref SCORE: Mutex<i32> = Mutex::new(0);
}

fn set_score_err(ns: i32, p: PoisonError<MutexGuard<i32>>) {
	if cfg!(ignore_poisoning) {
		*p.into_inner() = ns;
	} else {
		panic!("{}", p);
	}
}

pub fn set_score(ns: i32) {
	match (*SCORE).lock() {
		Ok(mut g) => *g = ns,
		Err(g) => set_score_err(ns, g),
	}
}

fn get_score_err(p: PoisonError<MutexGuard<i32>>) -> i32 {
	if cfg!(ignore_poisoning) {
		*p.into_inner()
	} else {
		panic!("{}", p)
	}
}

pub fn get_score() -> i32 {
	match (*SCORE).lock() {
		Ok(mut g) => *g,
		Err(g) => get_score_err(g),
	}
}

fn add_score_err(add: i32, p: PoisonError<MutexGuard<i32>>) -> i32 {
	if cfg!(ignore_poisoning) {
		let mut g = p.into_inner();
		*g += add;
		*g
	} else {
		panic!("{}", p)
	}
}

pub fn add_score(add: i32) -> i32 {
	match (*SCORE).lock() {
		Ok(mut g) => {
			*g += add;
			*g
		},
		Err(g) => get_score_err(g),
	}
}

pub fn sub_score(sub: i32) -> i32 {
	add_score(!sub)
}