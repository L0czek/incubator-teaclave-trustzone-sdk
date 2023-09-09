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

#![feature(try_reserve)]
#![feature(asm)]

use optee_teec::{Context, Operation, ParamType, Session, Uuid, Param, ParamTmpRef};
use optee_teec::{ParamNone, ParamValue};
use proto::{UUID, Command, TestcaseDecodingMode};
use clap::{Command as ClapCommand, arg, value_parser};
use std::string::String;

mod fuzzer;

fn main() -> optee_teec::Result<()> {
    let cmd = ClapCommand::new("Fuzzer")
        .arg(
            arg!(-t --testcase <TESTCASE> "Testcase to check, insted of start fuzzing")
            .required(false)
            .value_parser(value_parser!(String))
            .exclusive(true)
        )
        .arg(
            arg!(-H --host_fuzzer "Run fuzzer from buildroot")
            .required(false)
            .id("host_fuzzer")
            .action(clap::ArgAction::SetTrue)
            .exclusive(true)
        )
        .arg(
            arg!(-n --no_reverts "Start fuzzing with no state saving")
            .required(false)
            .id("no_reverts")
            .action(clap::ArgAction::SetTrue)
            .exclusive(true)
        )
        .arg(
            arg!(-g --generate_testcases "Generate testcases from tests")
            .required(false)
            .id("generate")
            .action(clap::ArgAction::SetTrue)
            .exclusive(true)
        )
        .arg(
            arg!(-e --exit "Send exit 0 to QEMU")
            .required(false)
            .id("exit")
            .action(clap::ArgAction::SetTrue)
            .exclusive(true)
        )
        .arg(
            arg!(-m --mode <MODE> "Set testcase decoding mode")
            .required(false)
            .id("mode")
            .value_parser(value_parser!(String))
        );

    let matches = cmd.get_matches();

    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    if let Some(mode) = matches.get_one::<String>("mode") {
        println!("mode: {:?}", mode);
        let m = match mode {
            x if x == "dsl" => TestcaseDecodingMode::Dsl,
            x if x == "direct" => TestcaseDecodingMode::Direct,
            _ => TestcaseDecodingMode::Invalid
        };

        if let TestcaseDecodingMode::Invalid = m {
            println!("Invalid decoding mode provided!");
        } else {
            let p = ParamValue::new(m as u32, 0, ParamType::ValueInput);
            let mut operation = Operation::new(0, p, ParamNone, ParamNone, ParamNone);
            session.invoke_command(Command::SetTestcaseDecodingMode as u32, &mut operation)?;
        }
    }

    if let Some(testcase) = matches.get_one::<String>("testcase") {
        println!("Run testcase {}", testcase);
        if let Ok(tc) = hex::decode(testcase.as_bytes()) {
            let p = ParamTmpRef::new_input(tc.as_slice());
            let mut operation = Operation::new(0, p, ParamNone, ParamNone, ParamNone);
            session.invoke_command(Command::RunTestcase as u32, &mut operation)?;
        } else {
            println!("Failed to decode testcase");
        }
    } else if matches.get_flag("host_fuzzer") {
        println!("Running fuzzing from buildroot");

        loop {
            let tc = fuzzer::fetch_testcase().expect("Failed to fetch testcase");
            let p = ParamTmpRef::new_input(tc.as_slice());
            let mut operation = Operation::new(0, p, ParamNone, ParamNone, ParamNone);
            session.invoke_command(Command::RunTestcaseWithCoverage as u32, &mut operation)?;
            fuzzer::exit_no_restore(0i8);
        }
    } else if matches.get_flag("no_reverts") {
        let mut operation = Operation::new(0, ParamNone, ParamNone, ParamNone, ParamNone);
        session.invoke_command(Command::StartFuzzingNoRevert as u32, &mut operation)?;
    } else if matches.get_flag("generate") {
        let mut operation = Operation::new(0, ParamNone, ParamNone, ParamNone, ParamNone);
        session.invoke_command(Command::GenerateTestcases as u32, &mut operation)?;
    } else if matches.get_flag("exit") {
        fuzzer::exit(0i8);
    } else {
        println!("Start fuzzing");
        let mut operation = Operation::new(0, ParamNone, ParamNone, ParamNone, ParamNone);
        session.invoke_command(Command::StartFuzzing as u32, &mut operation)?;
    }

    println!("Success");
    Ok(())
}
