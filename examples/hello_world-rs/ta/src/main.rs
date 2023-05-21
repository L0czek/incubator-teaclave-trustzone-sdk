// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

#![no_main]

use api::Creds;
use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::Command;
use lazy_static::lazy_static;
use std::sync::Mutex;

use crate::api::{Key, Slot, TPM};

mod tpm;
mod creds;
mod handler;
mod request;
mod serialize;
mod api;
mod error;

#[ta_create]
fn create() -> Result<()> {
    trace_println!("[+] TA create");
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA open session");
    Ok(())
}

#[ta_close_session]
fn close_session() {
    trace_println!("[+] TA close session");
}

#[ta_destroy]
fn destroy() {
    trace_println!("[+] TA destroy");
}

fn test_api() -> Result<()>{
    let user = Creds::register("user".to_string(), "user".to_string()).expect("Failed to register user");
    let _creds = Creds::login("user".to_string(), "user".to_string()).expect("Failed to login");

    let key = Key::new(&user);
    key.set([1u8;32]);

    let slot = Slot::new().expect("cannot alloc slot");
    let _data = vec![1,2,3];
    slot.set(_data.clone()).expect("Cannot save to slot");
    assert!(slot.get().expect("Cannot read from slot") == _data);

    let tpm = TPM::new();
    let _secret = vec![5,6,7];
    tpm.lock(_secret.clone(), &user, &slot).expect("Cannot lock slot");

    let slot2 = Slot::new().expect("Cannot alloc slot");
    tpm.unlock(_secret.clone(), &user, &slot2).expect("Cannot unlock slot");
    let _data_read = slot2.get().expect("Cannot read from slot");
    trace_println!("{:?} == {:?}", _data_read, _data);
    assert!(_data_read == _data);

    trace_println!("unit test success");
    Ok(())
}

#[ta_invoke_command]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    trace_println!("[+] TA invoke command");
    match Command::from(cmd_id) {
        Command::ApiCall => test_api(),
        _ => Err(Error::new(ErrorKind::BadParameters)),
    }
}

// TA configurations
const TA_FLAGS: u32 = 0;
const TA_DATA_SIZE: u32 = 32 * 1024;
const TA_STACK_SIZE: u32 = 2 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"This is a hello world example.\0";
const EXT_PROP_VALUE_1: &[u8] = b"Hello World TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
