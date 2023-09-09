use super::request::KeyType;
use super::{
    error::Error,
    handler,
    request::{Request, Response},
    serialize::{Deserialize, Deserializer, Serialize, Serializer},
};
use lazy_static::lazy_static;
use std::sync::Mutex;

lazy_static! {
    pub static ref HANDLER: Mutex<handler::Handler> = Mutex::new(handler::Handler::new());
}


#[derive(Debug)]
pub struct Creds {
    uid: usize,
}

#[derive(Debug)]
pub struct Key {
    uid: usize,
    keyid: Option<usize>,
}

#[derive(Debug)]
pub struct Slot {
    slotid: usize,
}

#[derive(Debug)]
pub struct TPM;

impl Creds {
    pub fn login(user: String, password: String) -> Result<Self, Error> {
        let req = Request::UserLogin(user, password);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Id(id) => Ok(Self { uid: id }),
            _ => Err(Error::InvalidResponse),
        }
    }

    pub fn register(user: String, password: String) -> Result<Self, Error> {
        let req = Request::UserRegister(user, password);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Id(id) => Ok(Self { uid: id }),
            _ => Err(Error::InvalidResponse),
        }
    }
}

impl Key {
    pub fn new(creds: &Creds) -> Self {
        Self {
            uid: creds.uid,
            keyid: None,
        }
    }

    pub fn get(&self) -> Result<KeyType, Error> {
        let req = Request::GetKeyForUser(self.uid);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Key(key) => Ok(key),
            _ => Err(Error::InvalidResponse),
        }
    }

    pub fn set(&self, key: KeyType) -> Result<(), Error> {
        let req = Request::SaveKeyForUser(self.uid, key);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Ok => Ok(()),
            _ => Err(Error::InvalidResponse),
        }
    }
}

impl Slot {
    pub fn new() -> Result<Self, Error> {
        let req = Request::AllocSlot();

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Id(slotid) => Ok(Self { slotid }),
            _ => Err(Error::InvalidResponse),
        }
    }

    pub fn set(&self, data: Vec<u8>) -> Result<(), Error> {
        let req = Request::SaveToSlot(self.slotid, data);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Ok => Ok(()),
            _ => Err(Error::InvalidResponse),
        }
    }

    pub fn get(&self) -> Result<Vec<u8>, Error> {
        let req = Request::GetFromSlot(self.slotid);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Data(data) => Ok(data),
            _ => Err(Error::InvalidResponse),
        }
    }

    pub fn setup(&self, flags: usize, size: usize) -> Result<(), Error> {
        let req = Request::SetupSlot(self.slotid, flags, size);

        let resp = Response::deserialize(&mut Deserializer::new(
                HANDLER.lock().unwrap().command(req.serialize().into()
        )))?;

        match resp {
            Response::Ok => Ok(()),
            _ => Err(Error::InvalidResponse)
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let req = Request::FreeSlot(self.slotid);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))
        .expect("Failed to deserialize response from api");

        match resp {
            Response::Ok => (),
            _ => panic!("Cannot free slot"),
        }
    }
}

impl TPM {
    pub fn new() -> Self {
        Self {}
    }

    pub fn lock(&self, data: Vec<u8>, creds: &Creds, slot: &Slot) -> Result<(), Error> {
        let req = Request::TpmLock(data, creds.uid, slot.slotid);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Ok => Ok(()),
            _ => Err(Error::InvalidResponse),
        }
    }

    pub fn unlock(&self, data: Vec<u8>, creds: &Creds, slot: &Slot) -> Result<(), Error> {
        let req = Request::TpmUnlock(data, creds.uid, slot.slotid);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Ok => Ok(()),
            _ => Err(Error::InvalidResponse),
        }
    }
}
