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
#![feature(asm)]
#![feature(try_reserve)]

extern crate dsl;

use optee_utee::{
    ta_close_session, ta_create, ta_destroy, ta_invoke_command, ta_open_session, trace_println,
};
use optee_utee::{Error, ErrorKind, Parameters, Result};
use proto::Command;

mod fuzz_target;
mod fuzzer;

dsl::target! {
    test [trace] {
        use {
            super::fuzz_target::api::Creds,
            super::fuzz_target::api::Key,
            super::fuzz_target::api::Slot,
            super::fuzz_target::api::TPM
        }

        Apis {
            Creds {
                ctors {
                    Creds::login(#Str(32), #Str(32)) -> Creds,
                    Creds::register(#Str(32), #Str(32)) -> Creds
                }
                functions {}
            },

            Key {
                ctors {
                    Ok Key::new(ref #Api(Creds)) -> Key
                }
                functions {
                    get() -> (),
                    set(#TPMKey) -> ()
                }
            },

            Slot {
                ctors {
                    Slot::new() -> Slot
                }
                functions {
                    set(#Vector(32)) -> (),
                    get() -> ()
                }
            },

            TPM {
                ctors {
                    Ok TPM::new() -> TPM
                }
                functions {
                    lock(#Vector(32), ref #Api(Creds), ref #Api(Slot)) -> (),
                    unlock(#Vector(32), ref #Api(Creds), ref #Api(Slot)) -> ()
                }
            }
        }
        Functions {
        }
    }
}

#[ta_create]
fn create() -> Result<()> {
    unsafe {
        trace_println!("[+] TA create");
    }
    Ok(())
}

#[ta_open_session]
fn open_session(_params: &mut Parameters) -> Result<()> {
    unsafe {
        trace_println!("[+] TA open session");
    }
    Ok(())
}

#[ta_close_session]
fn close_session() {
    unsafe {
        trace_println!("[+] TA close session");
    }
}

#[ta_destroy]
fn destroy() {
    unsafe {
        trace_println!("[+] TA destroy");
    }
}

fn start_fuzzing() {
    unsafe {
        trace_println!("Fuzzer: start command");
    }
    fuzzer::log("Starting fuzzer...");

    if let Err(err) = fuzzer::run(|tc| {
        test::fuzz(tc);
    }) {
        unsafe {
            trace_println!("Error while fuzzing: {:?}", err);
        }
    }
    fuzzer::exit(0i8);
}

fn run_testcase(tc: &[u8]) {
    unsafe {
        trace_println!("Fuzzer run testcase: {:?}", tc);
        test::fuzz(tc);
    }
}

#[ta_invoke_command]
fn invoke_command(cmd_id: u32, params: &mut Parameters) -> Result<()> {
    unsafe {
        trace_println!("[+] TA invoke command");
    }
    match Command::from(cmd_id) {
        Command::StartFuzzing => start_fuzzing(),
        Command::RunTestcase => run_testcase(unsafe { params.0.as_memref() }?.buffer()),
        _ => return Err(Error::new(ErrorKind::BadParameters)),
    };

    Ok(())
}

// TA configurations
const TA_FLAGS: u32 = 0;
const TA_DATA_SIZE: u32 = 32 * 1024;
const TA_STACK_SIZE: u32 = 2 * 1024;
const TA_VERSION: &[u8] = b"0.1\0";
const TA_DESCRIPTION: &[u8] = b"This is a fuzzing app.\0";
const EXT_PROP_VALUE_1: &[u8] = b"Fuzzing TA\0";
const EXT_PROP_VALUE_2: u32 = 0x0010;
const TRACE_LEVEL: i32 = 4;
const TRACE_EXT_PREFIX: &[u8] = b"TA\0";
const TA_FRAMEWORK_STACK_SIZE: u32 = 2048;

include!(concat!(env!("OUT_DIR"), "/user_ta_header.rs"));
