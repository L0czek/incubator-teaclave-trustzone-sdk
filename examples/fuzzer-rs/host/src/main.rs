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
use proto::{UUID, Command};
use clap::{Command as ClapCommand, arg, value_parser};
use std::string::String;

mod fuzzer;

fn main() -> optee_teec::Result<()> {
    let cmd = ClapCommand::new("Fuzzer")
        .arg(
            arg!(-t --testcase <TESTCASE> "Testcase to check, insted of start fuzzing")
            .required(false)
            .value_parser(value_parser!(String))
        )
        .arg(
            arg!(-H --host_fuzzer "Run fuzzer from buildroot")
            .required(false)
            .id("host_fuzzer")
            .action(clap::ArgAction::SetTrue)
        )
        .arg(
            arg!(-n --no_reverts "Start fuzzing with no state saving")
            .required(false)
            .id("no_reverts")
            .action(clap::ArgAction::SetTrue)
        );

    let matches = cmd.get_matches();

    let mut ctx = Context::new()?;
    let uuid = Uuid::parse_str(UUID).unwrap();
    let mut session = ctx.open_session(uuid)?;

    if let Some(testcase) = matches.get_one::<String>("testcase") {
        println!("Run testcase {}", testcase);
        let p = ParamTmpRef::new_input(testcase.as_bytes());
        let mut operation = Operation::new(0, p, ParamNone, ParamNone, ParamNone);
        session.invoke_command(Command::RunTestcase as u32, &mut operation)?;
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
    } else {
        println!("Start fuzzing");
        let mut operation = Operation::new(0, ParamNone, ParamNone, ParamNone, ParamNone);
        session.invoke_command(Command::StartFuzzing as u32, &mut operation)?;
    }

    println!("Success");
    Ok(())
}
