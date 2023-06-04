use super::request::KeyType;
use super::{
    error::Error,
    handler,
    request::{Request, Response},
    serialize::{Deserialize, Deserializer, Serialize, Serializer},
};
use lazy_static::lazy_static;
use std::sync::Mutex;
use crate::test::{Id, Apis, TcAssembler, encodings};
use crate::tcgen_macros::*;

lazy_static! {
    static ref HANDLER: Mutex<handler::Handler> = Mutex::new(handler::Handler::new());
}
use dsl::{add_id_field, impl_id, tcgen_ctor, tcgen_member};

#[add_id_field]
#[derive(Debug, Default)]
pub struct Creds {
    uid: usize,
}

#[add_id_field]
#[derive(Debug, Default)]
pub struct Key {
    uid: usize,
    keyid: Option<usize>,
}

#[add_id_field]
#[derive(Debug, Default)]
pub struct Slot {
    slotid: usize,
}

#[add_id_field]
#[derive(Debug, Default)]
pub struct TPM {}

impl Creds {
    #[tcgen_ctor(Creds, Creds::login)]
    pub fn login(user: String, password: String) -> Result<Self, Error> {
        let req = Request::UserLogin(user, password);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Id(id) => Ok(Self { uid: id, ..Default::default()}),
            _ => Err(Error::InvalidResponse),
        }
    }

    #[tcgen_ctor(Creds, Creds::register)]
    pub fn register(user: String, password: String) -> Result<Self, Error> {
        let req = Request::UserRegster(user, password);

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Id(id) => Ok(Self { uid: id, ..Default::default() }),
            _ => Err(Error::InvalidResponse),
        }
    }
}

impl_id! { Creds }

impl Key {
    #[tcgen_ctor(Key, Key::new)]
    pub fn new(creds: &Creds) -> Self {
        Self {
            uid: creds.uid,
            keyid: None,
            ..Default::default()
        }
    }

    #[tcgen_member(Key)]
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

    #[tcgen_member(Key)]
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

impl_id! { Key }

impl Slot {
    #[tcgen_ctor(Slot, Slot::new)]
    pub fn new() -> Result<Self, Error> {
        let req = Request::AllocSlot();

        let resp = Response::deserialize(&mut Deserializer::new(
            HANDLER.lock().unwrap().command(req.serialize().into()),
        ))?;

        match resp {
            Response::Id(slotid) => Ok(Self { slotid, ..Default::default() }),
            _ => Err(Error::InvalidResponse),
        }
    }

    #[tcgen_member(Slot)]
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

    #[tcgen_member(Slot)]
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

impl_id! { Slot }

impl TPM {
    #[tcgen_ctor(TPM, TPM::new)]
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    #[tcgen_member(TPM)]
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

    #[tcgen_member(TPM)]
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

impl_id! { TPM }

pub mod tc {
    use dsl::tcgen_record;

    use super::*;
    use crate::{trace_println, fuzzer::save_tc_to_file};

    #[tcgen_record]
    fn register_user() {
        let user = Creds::register("123".to_string(), "456".to_string());
    }

    pub fn run_all_tc() {
        TcAssembler::take()
            .set_tc_save_routine(|name, tc| {
                trace_println!("TC[{}] = {:?}", name, tc);
                save_tc_to_file(name, tc);
            });

        register_user();
    }
}
