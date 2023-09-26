/*  
*   SPDX-License-Identifier: GPL-3.0-only
*   A cyberpatriots scoring engine library
*   Copyright (C) 2023 Teresa Maria Rivera
*/
use std::{
    string::String, 
    fs::File, 
    io::{BufReader, Read},
    sync::Mutex, 
    collections::BTreeMap,
    ptr::{null_mut, null},
};
use lazy_static::lazy_static;

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

#[derive(Clone, PartialEq, Eq)]
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

fn get_named_data_json(name: &str) -> Value {
    use serde_json::Value as JsonValue;

    match (*DATA_DB_FILES).lock() {
        Ok(mut g) => {
            let mut ret: JsonValue = JsonValue::Null;
            for i in &*g {
                let mut f = match File::open(i.as_str()) {
                    Ok(file) => file,
                    Err(_) => panic!("Can't open data file {}", name),
                };
                let v: JsonValue = match serde_json::from_reader(BufReader::new(f)).ok() {
                    Some(v) => v,
                    None => continue,
                };

                match v.get(name) {
                    Some(val) => {
                        ret = val.clone();
                        break;
                    },
                    None => ret = JsonValue::Null,
                }
            }

            Value::from_serde_json_value(ret)
        },
        Err(_) => todo!(),
    }
}

fn get_named_data_yaml(name: &str) -> Value {
    use serde_yaml::Value as YamlValue;

    match (*DATA_DB_FILES).lock() {
        Ok(mut g) => {
            let mut ret: YamlValue = YamlValue::Null;
            for i in &*g {
                let f = match File::open(i.as_str()) {
                    Ok(file) => file,
                    Err(_) => panic!("Can't open data file {}", name),
                };
                let v: YamlValue = match serde_yaml::from_reader(BufReader::new(f)) {
                    Ok(yaml) => yaml,
                    Err(_) => continue,
                };

                match v.get(name) {
                    Some(val) => {
                        ret = val.clone();
                        break;
                    },
                    None => ret = YamlValue::Null,
                }
            }

            Value::from_serde_yaml_value(ret)
        },
        Err(_) => todo!(),
    }
}

fn get_named_data_toml(name: &str) -> Value {
    use toml::Value as TomlValue;
    use toml::Table;

    match (*DATA_DB_FILES).lock() {
        Ok(mut g) => {
            // Null sentinel, TODO: new solution
            let mut ret: TomlValue = unsafe { TomlValue::String(String::from_raw_parts(null_mut(), 0, 0)) };
            for i in &*g {
                let mut f = match File::open(i.as_str()) {
                    Ok(file) => file,
                    Err(_) => panic!("Can't open data file {}", name),
                };

                let mut string = String::new();
                f.read_to_string(&mut string);

                let v: Table = match toml::from_str(string.as_str()) {
                    Ok(toml) => toml,
                    Err(_) =>continue,
                };

                match v.get(name) {
                    Some(val) => {
                        ret = val.clone();
                        break;
                    },
                    None => continue,
                }
            }

            Value::from_serde_toml_value(ret)
        },
        Err(_) => todo!(),
    }
}

pub fn get_database_entry(name: &str) -> Value {
    let mut r = get_named_data_json(name);

    if r != Value::Null {
        return r;
    }

    r = get_named_data_yaml(name);

    if r != Value::Null {
        return r;
    }

    r = get_named_data_toml(name);

    if r != Value::Null {
        return r;
    }

    Value::Null
}

impl PartialEq for Number {
    fn eq(&self, other: &Self) -> bool {
        if self.typo == other.typo {
            if self.typo {
                unsafe { self.numero.integer == other.numero.integer }
            } else {
                unsafe { self.numero.float == other.numero.float }
            }
        } else {
            false
        }
    }
}

impl Eq for Number {}

impl Number {
    fn from_json_number(n: serde_json::Number) -> Self {
        let mut a = Number { typo: true, numero: _Number { integer: 0 } };
        if n.is_i64() {
            unsafe { a.numero.integer = n.as_i64().unwrap() as u64 }
        } else if n.is_u64() {
            unsafe { a.numero.integer = n.as_u64().unwrap() }
        } else {
            a.typo = false;
            unsafe { a.numero.float = n.as_f64().unwrap() }
        }

        a
    }
    fn from_yaml_number(n: serde_yaml::Number) -> Self {
        let mut a = Number { typo: true, numero: _Number { integer: 0 } };
        if n.is_i64() {
            unsafe { a.numero.integer = n.as_i64().unwrap() as u64 }
        } else if n.is_u64() {
            unsafe { a.numero.integer = n.as_u64().unwrap() }
        } else {
            a.typo = false;
            unsafe { a.numero.float = n.as_f64().unwrap() }
        }

        a
    }
    fn from_toml_number(n: toml::Value) -> Self {
        match n {
            toml::Value::Integer(i) => Number { typo: true, numero: _Number { integer: i as u64 } },
            toml::Value::Float(f) => Number { typo: false, numero: _Number { float: f } },
            _ => Number { typo: false, numero: _Number { float: f64::NAN } },
        }
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
    fn from_serde_json_value(v: serde_json::Value) -> Self {
        match v {
            serde_json::Value::Null => Self::Null,
            serde_json::Value::Bool(b) => Self::Bool(b),
            serde_json::Value::Number(numero) => Self::Number(Number::from_json_number(numero)),
            serde_json::Value::String(string) => Self::String(string),
            serde_json::Value::Array(v) => {
                let mut vector = Vec::with_capacity(v.len());

                for i in v {
                    vector.push(Self::from_serde_json_value(i));
                }

                Self::Array(vector)
            },
            serde_json::Value::Object(m) => {
                let mut map = BTreeMap::new();

                for i in m.into_iter() {
                    map.insert(i.0.clone(), Self::from_serde_json_value(i.1.clone()));
                }

                Self::Object(map)
            },
        }	
    }

    fn from_serde_yaml_value(v: serde_yaml::Value) -> Self {
        match v {
            serde_yaml::Value::Null => Self::Null,
            serde_yaml::Value::Bool(b) => Self::Bool(b),
            serde_yaml::Value::Number(numero) => Self::Number(Number::from_yaml_number(numero)),
            serde_yaml::Value::String(string) => Self::String(string),
            serde_yaml::Value::Sequence(v) => {
                let mut vector = Vec::with_capacity(v.len());

                for i in v {
                    vector.push(Self::from_serde_yaml_value(i));
                }

                Self::Array(vector)
            },
            serde_yaml::Value::Mapping(m) => todo!(),
            serde_yaml::Value::Tagged(b) => {
                Self::from_serde_yaml_value((*b).value)
            },
        }
    }

    fn from_serde_toml_value(v: toml::Value) -> Self {
        match v {
            toml::Value::Boolean(b) => Self::Bool(b),
            toml::Value::Integer(_) | toml::Value::Float(_) => Self::Number(Number::from_toml_number(v)),
            toml::Value::String(string) => {
                if string.as_bytes().as_ptr() != null() {
                    Self::Null
                } else {
                    Self::String(string)
                }
            },
            toml::Value::Array(v) => {
                let mut vector = Vec::with_capacity(v.len());

                for i in v {
                    vector.push(Self::from_serde_toml_value(i));
                }

                Self::Array(vector)
            },
            toml::Value::Table(t) => {
                let mut map = BTreeMap::new();

                for i in t.into_iter() {
                    map.insert(i.0.clone(), Self::from_serde_toml_value(i.1.clone()));
                }

                Self::Object(map)
            },
            toml::Value::Datetime(d) => Self::String(format!("{}", d)),
        }
    }
}