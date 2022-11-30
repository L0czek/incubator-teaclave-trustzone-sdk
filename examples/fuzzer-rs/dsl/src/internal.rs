use std::vec::Vec;
use std::mem::size_of;
use std::convert::TryInto;
use super::{Objects, Apis};
use optee_utee::trace_println;

pub enum FuzzerError {
    EndOfInput,
    FailedToCreateObject,
    ObjectIsOfInvalidType,
    EmptySliceThereIsNoChoice,
}

type ctor = fn (&Target, &mut Buffer) -> Result<Objects, FuzzerError>;
type function = fn (&Target, &mut Objects, &mut Buffer) -> Result<Objects, FuzzerError>;
type nonmember_function = fn (&Target, &mut Buffer) -> Result<(), FuzzerError>;

pub struct Api {
    ctors: Vec<ctor>,
    funcs: Vec<function>
}

impl Api {
    pub fn new(ctors: Vec<ctor>, funcs: Vec<function>) -> Self {
        Self { ctors, funcs }
    }

    fn fuzz(&self, target: &Target, buffer: &mut Buffer) -> Result<Objects, FuzzerError> {
        const MAX_CALLS: usize = 10;

        let init = buffer.slice_choice(&self.ctors)?;
        let mut obj = init(target, buffer)?;

        if !self.funcs.is_empty() {
            for i in 0..buffer.get_u8()? as usize % MAX_CALLS {
                let func = buffer.slice_choice(&self.funcs)?;
                let ret = func(target, &mut obj, buffer)?;

                match ret {
                    Objects::None => {},
                    val => { obj = val }
                }
            }
        }

        Ok(obj)
    }
}

pub struct Target {
    apis: Vec<Api>,
    funcs: Vec<nonmember_function>
}

impl Target {
    pub fn new(apis: Vec<Api>, funcs: Vec<nonmember_function>) -> Self {
        Self { apis, funcs }
    }

    pub fn api(&self, ident: Apis) -> &Api {
        &self.apis[ident as usize]
    }

    pub fn fuzz(&self, buffer: &mut Buffer) -> Result<(), FuzzerError> {
        let apis = self.apis.len();
        let funcs = self.funcs.len();

        loop {
            let idx = buffer.get_u8()? as usize % (apis + funcs);

            if idx < apis && !self.apis.is_empty() {
                self.apis[idx].fuzz(self, buffer)?;
            } else if !self.funcs.is_empty() {
                self.funcs[idx - apis](self, buffer)?;
            }
        }
    }

    pub fn fuzz_api(&self, ident: Apis, buffer: &mut Buffer) -> Result<Objects, FuzzerError> {
        self.api(ident).fuzz(self, buffer)
    }
}

pub struct Buffer<'a> {
    data: &'a [u8],
    it: usize
}

impl<'a> Buffer<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { data: buffer, it: 0usize }
    }

    pub fn slice(&mut self, n: usize) -> Result<&'a [u8], FuzzerError> {
        let remain = self.data.len() - self.it;
        if remain >= n {
            let ret = &self.data[self.it..self.it+n];
            self.it += n;
            Ok(ret)
        } else {
            trace_println!("testcase has ended, exiting");
            Err(FuzzerError::EndOfInput)
        }
    }

    pub fn vec(&mut self, n: usize) -> Result<Vec<u8>, FuzzerError> {
        Ok(self.slice(n)?.to_vec())
    }

    pub fn get_u8(&mut self) -> Result<u8, FuzzerError> {
        Ok(u8::from_le_bytes(self.slice(size_of::<u8>())?.try_into().unwrap()))
    }

    pub fn get_u16(&mut self) -> Result<u16, FuzzerError> {
        Ok(u16::from_le_bytes(self.slice(size_of::<u16>())?.try_into().unwrap()))
    }

    pub fn get_u32(&mut self) -> Result<u32, FuzzerError> {
        Ok(u32::from_le_bytes(self.slice(size_of::<u32>())?.try_into().unwrap()))
    }

    pub fn get_u64(&mut self) -> Result<u64, FuzzerError> {
        Ok(u64::from_le_bytes(self.slice(size_of::<u64>())?.try_into().unwrap()))
    }

    pub fn uszie_array(&mut self, n: usize) -> Result<Vec<usize>, FuzzerError> {
        (0..n).map(|_| self.get_u64().map(|v| v as usize)).collect::<Result<Vec<usize>, FuzzerError>>()
    }

    pub fn slice_choice<'b, T: Sized>(&mut self, slice: &'b [T]) -> Result<&'b T, FuzzerError> {
        if slice.is_empty() {
            trace_println!("Provided slice is empty!");
            return Err(FuzzerError::EmptySliceThereIsNoChoice);
        }

        let index = self.get_u8()?;
        let total_len = slice.len();
        Ok(slice.iter().nth(index as usize % total_len).unwrap())
    }
}
