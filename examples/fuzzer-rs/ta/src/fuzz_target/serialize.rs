use super::error::Error;
use std::convert::TryInto;

pub(super) struct Serializer {
    data: Vec<u8>,
}

impl Serializer {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
        }
    }

    pub fn push_u8(&mut self, v: u8) { self.data.push(v) }
    pub fn push_u32(&mut self, v: u32) { self.data.extend(&v.to_le_bytes()); }
    pub fn push_usize(&mut self, v: usize) { self.data.extend(&v.to_le_bytes()); }
    pub fn push_data(&mut self, v: &[u8]) {
        self.push_u32(v.len() as u32);
        self.data.extend(v);
    }
    pub fn push_string(&mut self, v: &String) {
        let data = v.as_bytes();
        self.push_u32(data.len() as u32);
        self.push_data(data);
    }
}

impl Into<Vec<u8>> for Serializer {
    fn into(self) -> Vec<u8> {
        self.data
    }
}

pub(super) trait Serialize {
    fn serialize(&self) -> Serializer;
}

pub(super) struct Deserializer {
    data: Vec<u8>,
    it: usize
}

impl Deserializer {
    pub fn new(data: Vec<u8>) -> Self { Self { data, it: 0usize } }

    pub fn pop_u8(&mut self) -> Result<u8, Error> {
        if let Some(v) = self.data.iter().skip(self.it).take(1).cloned().next() {
            self.it += 1;
            Ok(v)
        } else {
            Err(Error::DeserializeEndOfInput)
        }
    }
    pub fn pop_u32(&mut self) -> Result<u32, Error> {
        match self.data.iter().skip(self.it).take(4).cloned().collect::<Vec<u8>>().as_slice().try_into() {
            Ok(v) => {
                self.it += 4;
                Ok(u32::from_le_bytes(v))
            },
            Err(_) => Err(Error::DeserializeEndOfInput)
        }
    }
    pub fn pop_usize(&mut self) -> Result<usize, Error> {
        match self.data.iter().skip(self.it).take(8).cloned().collect::<Vec<u8>>().as_slice().try_into() {
            Ok(v) => {
                self.it += 8;
                Ok(usize::from_le_bytes(v))
            },
            Err(_) => Err(Error::DeserializeEndOfInput)
        }
    }
    pub fn pop_data(&mut self) -> Result<Vec<u8>, Error> {
        let size = self.pop_u32()?;
        match self.data.iter().skip(self.it).take(size as usize).cloned().collect::<Vec<u8>>().try_into() {
            Ok(v) => {
                self.it += size as usize;
                Ok(v)
            },
            Err(_) => Err(Error::DeserializeEndOfInput)
        }
    }
    pub fn pop_string(&mut self) -> Result<String, Error> {
        let v = self.pop_data()?;
        match String::from_utf8(v) {
            Ok(v) => Ok(v),
            Err(_) => Err(Error::DeserializeEndOfInput)
        }
    }

}

pub(super) trait Deserialize {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, Error> where Self: Sized;
}

