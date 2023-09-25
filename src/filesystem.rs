/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/
use crate::state::{add_vuln, ConditionData::*, add_score, FileData};
use sha2::{Sha256, Digest};
use digest::Output;
use std::{
	string::String, 
	fs::File, 
	io::BufReader,
	sync::Mutex, 
	collections::BTreeMap
};
use lazy_static::lazy_static;

pub type FileHash = Output<Sha256>;

lazy_static! {
	static ref DATA_DB_FILES: Mutex<Vec<String>> = Mutex::new(Vec::with_capacity(32));
}

#[derive(Clone, Copy)]
union _Number {
	integer: u64,
	float: f64,
}

#[derive(Clone, Copy)]
pub struct Number {
	typo: bool,
	numero: _Number,
}

#[derive(Clone)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(BTreeMap<String, Value>),
}

pub fn register_db_file(name: &String) {
	match (*DATA_DB_FILES).lock() {
		Ok(mut g) => g.push(name.clone()),
		Err(g) => {
			if cfg!(ignore_poisoning) {
                g.into_inner().push(name.clone());
            } else {
                panic!("{}", g);
            }
		}
	}
}

#[cfg(json_data)]
fn get_named_data_yaml(name: &str) -> Value {
	match (*DATA_DB_FILES).lock() {
		Ok(mut g) => {
			let ret: Value;
			for &i in *g {
				let mut f = match File::open(i.as_str()) {
					Result(file) => file,
					Err => panic!("Can't open data file {}", name),
				};
				let v: BTreeMap<&str, serde_yaml::Value> = match serde_yaml::from_reader(BufReader::new(f)) {
					Result(yaml) => yaml,
					Err => continue,
				};

				match v.get(name) {
					Some(val) => {
						ret = val;
						break;
					},
					None => ret = Value::Null,
				}
			}
		},
		Err => todo!(),
	}
}

#[cfg(yaml_data)]
fn get_named_data_json(name: &str) -> Value {
	use serde_yaml::Value as YamlValue;

	match (*DATA_DB_FILES).lock() {
		Ok(mut g) => {
			let ret: JsonValue;
			for &i in *g {
				let mut f = match File::open(i.as_str()) {
					Result(file) => file,
					Err => panic!("Can't open data file {}", name),
				};
				let v = serde_json::from_reader(BufReader::new(f));

				match v.get(name) {
					Some(val) => {
						ret = val;
						break;
					},
					None => ret = YamlValue::Null,
				}
			}

			Value::from_serde_yaml_value(ret)
		},
		Err => todo!(),
	}
}

// TODO: mas
pub fn get_named_data(name: &str) -> Value {
	#[cfg(json_data)]
	{
		let r = get_named_data_json(name);

		if r != Null {
			return r;
		}
	}

	#[cfg(yaml_data)]
	{
		let r = get_named_data_yaml(name);

		if r != Null {
			return r;
		}
	}

	Value::Null
}

impl Number {
	#[cfg(json_data)]
	fn from_json_number(n: serde_json::Number) -> Self {
		let a = Number { typo: true, numero: _Number { integer: 0 } };
		if n.is_i64() {
			unsafe { a.numero.integer = n.as_i64() }
		} else if n.is_u64() {
			unsafe { a.numero.integer = n.as_u64() }
		} else {
			a.typo = false;
			unsafe { a.numero.float = n.as_f64() }
		}

		a
	}

	#[cfg(yaml_data)]
	fn from_yaml_number(n: serde_yaml::Number) -> Self {
		let a = Number { typo: true, numero: _Number { integer: 0 } };
		if n.is_i64() {
			unsafe { a.numero.integer = n.as_i64() }
		} else if n.is_u64() {
			unsafe { a.numero.integer = n.as_u64() }
		} else {
			a.typo = false;
			unsafe { a.numero.float = n.as_f64() }
		}

		a
	}

	pub fn is_int(&self) -> bool {
		self.typo
	}

	pub fn is_float(&self) -> bool {
		!self.typo
	}

	pub fn as_u64(&self) -> u64 {
		unsafe { self.numero.integer }
	}

	pub fn as_i64(&self) -> i64 {
		unsafe { self.numero.integer as i64 }
	}  

	pub fn as_u32(&self) -> u32 {
		unsafe { self.numero.integer as u32 }
	}

	pub fn as_i32(&self) -> i32 {
		unsafe {  self.numero.integer as i32 }
	} 

	pub fn as_u16(&self) -> u16 {
		unsafe { self.numero.integer as u16 }
	}

	pub fn as_i16(&self) -> i16 {
		unsafe { self.numero.integer as i16 }
	} 

	pub fn as_u8(&self) -> u8 {
		unsafe { self.numero.integer as u8 }
	}

	pub fn as_i8(&self) -> i8 {
		unsafe { self.numero.integer as i8 }
	}

	pub fn as_f64(&self) -> f64 {
		unsafe { self.numero.float }
	}

	pub fn as_f32(&self) -> f32 {
		unsafe { self.numero.float as f32 }
	} 
}

impl Value {
	#[cfg(json_data)]
	fn from_serde_json_value(v: serde_json::Value) -> Self {
		match v {
			Null => Null,
			Bool(b) => Bool(b),
			Number(numero) => Number::from_json_number(numero),
			String(string) => String(string),
			Array(v) => {
				let vector = Vec::with_capacity(v.len());

				for i in v {
					vector.push(from_serde_json_value(i));
				}

				Array(vector)
			},
			Object(m) => {
				let map = BTreeMap::new();

				for i in m.into_inner() {
					map.insert(i.0.clone(), from_serde_json_value(i.1.clone()));
				}

				Object(map)
			},
		}	
	}

	#[cfg(yaml_data)]
	fn from_serde_yaml_value(v: serde_yaml::Value) -> Self {
		match v {
			Null => Null,
			Bool(b) => Bool(b),
			Number(numero) => Number::from_yaml_number(numero),
			String(string) => String(string),
			Sequence(v) => {
				let vector = Vec::with_capacity(v.len());

				for i in v {
					vector.push(from_serde_json_value(i));
				}

				Array(vector)
			},
			Mapping(m) => {
				let map = BTreeMap::new();

				for i in m.into_inner() {
					map.insert(i.0.clone(), from_serde_json_value(i.1.clone()));
				}

				Object(map)
			},
			TaggedValue(b) => {
				from_serde_yaml_value(*b.value)
			},
		}	
	}
}