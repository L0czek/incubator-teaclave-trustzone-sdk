use std::vec::Vec;
use std::mem::size_of;
use std::convert::TryInto;
use std::collections::HashMap;
use std::rc::Rc;
use super::{Objects, Apis};
use optee_utee::trace_println;
use std::sync::{Mutex, MutexGuard, Arc};

pub enum FuzzerError {
    EndOfInput,
    FailedToCreateObject,
    ObjectIsOfInvalidType,
    EmptySliceThereIsNoChoice,
    Utf8Decoding,
}

type ctor = fn (&Target, &mut Buffer) -> Result<Objects, FuzzerError>;
type function = fn (&Target, &mut Objects, &mut Buffer) -> Result<Objects, FuzzerError>;
type nonmember_function = fn (&Target, &mut Buffer) -> Result<(), FuzzerError>;

pub struct Api {
    ctors: Vec<ctor>,
    funcs: Vec<function>,
    api: Apis
}

impl Api {
    pub fn new(api: Apis, ctors: Vec<ctor>, funcs: Vec<function>) -> Self {
        Self { api, ctors, funcs }
    }

    fn fuzz(&self, target: &Target, buffer: &mut Buffer) -> Result<(), FuzzerError> {
        const MAX_CALLS: usize = 2;

        let idx = buffer.get_u8()? as usize;
        let obj = if idx >= 128 {
            None
        } else {
            buffer.get_cache(&self.api, idx)
        };

        let (mut o, el) = match obj {
            Some((o, el)) => (*o, Some(el)),
            None => {
                let init = buffer.slice_choice(&self.ctors)?;
                (init(target, buffer)?, None)
            }
        };

        let mut it = 0;

        loop {
            if buffer.get_u8()? % 2 == 0 || it >= MAX_CALLS {
                break;
            }

            if self.funcs.is_empty() {
                break;
            }

            let func = buffer.slice_choice(&self.funcs)?;
            let ret = func(target, &mut o, buffer)?;
            it += 1;

            match ret {
                Objects::None => {},
                val => { o = val }
            }
        }

        buffer.add_cache(self.api, Box::new(o), el);

        Ok(())
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

    pub fn fuzz_api(&self, ident: Apis, buffer: &mut Buffer) -> Result<(), FuzzerError> {
        self.api(ident).fuzz(self, buffer)
    }
}

pub struct Buffer<'a> {
    data: &'a [u8],
    it: usize,
    cache: HashMap<Apis, Vec<Option<Box<Objects>>>>
}

impl<'a> Buffer<'a> {
    pub fn new(buffer: &'a [u8]) -> Self {
        Self { data: buffer, it: 0usize, cache: HashMap::new() }
    }

    pub fn add_cache(&mut self, api: Apis, obj: Box<Objects>, idx: Option<usize>) {
        let objs = self.cache.entry(api).or_insert(Vec::new());

        if let Some(idx) = idx {
            std::mem::replace(&mut objs[idx], Some(obj));
        } else {
            objs.push(Some(obj));
        }
    }

    pub fn get_cache(&mut self, api: &Apis, idx: usize) -> Option<(Box<Objects>, usize)> {
        match self.cache.get_mut(api) {
            None => None,
            Some(vec) => {
                if vec.is_empty() {
                    None
                } else {
                    let el = idx % vec.len();
                    std::mem::replace(&mut vec[el], None)
                        .map(|o| (o, el))
                }
            }
        }
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

pub struct TcAssembler {
    tc: Vec<u8>,
    ids: HashMap<Apis, usize>,
    last_api: Option<u8>,
    tc_name: String,
    tc_save: Option<Box<fn (&str, &[u8]) -> ()>>
}

impl TcAssembler {
    fn new() -> Self {
        Self {
            tc: Vec::new(),
            ids: HashMap::new(),
            last_api: None,
            tc_name: String::new(),
            tc_save: None
        }
    }

    pub fn enter(&mut self, tcname: &str) {
        self.tc.clear();
        self.tc_name = tcname.to_string();
    }

    pub fn leave(&mut self) {
        trace_println!("[[TCGEN]] Assembled testcase {}", self.tc_name);

        if let Some(save_testcase) = self.tc_save.as_ref() {
            save_testcase(&self.tc_name, self.tc.as_slice());
        }

        self.ids.clear();
        self.last_api = None;
    }

    pub fn set_tc_save_routine(&mut self, func: fn (&str, &[u8]) -> ()) {
        self.tc_save = Some(Box::new(func));
    }

    pub fn add_byte(&mut self, v: u8) -> &mut Self {
        self.tc.push(v);
        self
    }

    pub fn add_bytes(&mut self, data: &[u8]) -> &mut Self {
        self.tc.extend(data);
        self
    }

    pub fn select_api(&mut self, api: u8, obj_id: Option<usize>) -> &mut Self {
        match self.last_api {
            Some(n) => {
                if n != api {
                    self.add_byte(0u8);
                    self.add_byte(api);
                    self.last_api = Some(api);

                    if let Some(obj) = obj_id {
                        self.use_obj(obj);
                    } else {
                        self.ctor_new_obj();
                    }
                }
            },
            None => {
                self.add_byte(api);
                self.ctor_new_obj();
                self.last_api = Some(api);
            }
        }

        self
    }

    pub fn ctor_new_obj(&mut self) -> &mut Self {
        self.add_byte(255u8)
    }

    pub fn use_obj(&mut self, id: usize) -> &mut Self {
        self.add_byte(id as u8)
    }

    pub fn select_ctor(&mut self, id: u8) -> &mut Self {
        self.add_byte(id);
        self
    }

    pub fn select_func(&mut self, id: u8) -> &mut Self {
        self.add_byte(1u8);
        self.add_byte(id)
    }

    pub fn alloc_id(&mut self, api: Apis) -> usize {
        let v = self.ids.entry(api).or_insert(0);
        let ret = *v;
        *v += 1;
        ret
    }

    pub fn take() -> MutexGuard<'static, Self> {
        use lazy_static::lazy_static;
        lazy_static! {
            static ref INSTANCE: Mutex<TcAssembler> = Mutex::new(TcAssembler::new());
        }
        INSTANCE.lock().unwrap()
    }
}

pub trait Id {
    fn __set_id__(&mut self);
    fn __get_id__(&self) -> usize;
}

