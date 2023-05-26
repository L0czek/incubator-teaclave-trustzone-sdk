use std::arch::asm;
use std::ptr::null;


#[derive(Debug)]
pub enum FuzzerError {
    OutOfRam,
    CannotReadTestCase,
}

pub enum Signals {
    SIGSEGV = 11,
}

pub fn forkserver() {
    unsafe {
        asm!("udf 137");
    }
}

pub fn begin() {
    unsafe {
        asm!("udf 138");
    }
}

pub fn end() {
    unsafe {
        asm!("udf 139");
    }
}

pub fn restrict_coverage(st: usize, en: usize) {
    unsafe {
        asm!(
            "udf 140",
            in ("x0") st,
            in ("x1") en
        )
    }
}

pub fn fetch_testcase() -> Result<Vec<u8>, FuzzerError> {
    let ptr: *const u8 = null();
    let mut len = 0usize;

    unsafe {
        asm!(
            "udf 141",
            in ("x0") ptr,
            inlateout ("x1") 0usize => len
        );
    }

    let mut data = Vec::new();
    data.try_reserve(len).map_err(|_| FuzzerError::OutOfRam)?;
    data.resize(len, 0u8);

    let ptr = data.as_mut_ptr();

    unsafe {
        asm!(
            "udf 141",
            in ("x0") ptr,
            inlateout ("x1") len => len
        );
    }

    if len == data.len() {
        Ok(data)
    } else {
        Err(FuzzerError::CannotReadTestCase)
    }
}

pub fn kill(signal: Signals) {
    unsafe {
        asm!(
            "udf 142",
            in ("x0") signal as i8
        )
    }
}

pub fn exit(code: i8) {
    unsafe {
        asm!(
            "udf 143",
            in ("x0") code
        )
    }
}

pub fn exit_no_restore(code: i8) {
    unsafe {
        asm!(
            "udf 145",
            in ("x0") code
        )
    }
}

pub fn run(target: fn(&[u8]) -> ()) -> Result<(), FuzzerError> {
    forkserver();

    let testcase = fetch_testcase()?;
    begin();
    target(testcase.as_slice());
    end();

    Ok(())
}

pub fn log(msg: &str) {
    unsafe {
        asm!(
            "udf 144",
            in ("x0") msg.as_ptr(),
            in ("x1") msg.len()
        )
    }
}
