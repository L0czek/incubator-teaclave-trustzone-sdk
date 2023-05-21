use crate::serialize::*;
use crate::error::Error;
use std::convert::TryInto;

pub(super) type KeyType = [u8; 32];

pub(super) enum Request {
    UserLogin(String, String),
    UserRegster(String, String),

    SaveKeyForUser(usize, KeyType),
    GetKeyForUser(usize),

    AllocSlot(),
    SaveToSlot(usize, Vec<u8>),
    GetFromSlot(usize),
    FreeSlot(usize),

    TpmLock(Vec<u8>, usize, usize),
    TpmUnlock(Vec<u8>, usize, usize)
}

#[repr(C)]
enum RequestIds {
    UserLogin = 1,
    UserRegster = 2,

    SaveKeyForUser = 3,
    GetKeyForUser = 4,

    AllocSlot = 5,
    SaveToSlot = 6,
    GetFromSlot = 7,
    FreeSlot = 8,

    TpmLock = 9,
    TpmUnlock = 10
}

impl Serialize for Request {
    fn serialize(&self) -> Serializer {
        let mut serializer = Serializer::new();

        match self {
            Request::UserLogin(login, pass) => {
                serializer.push_u32(RequestIds::UserLogin as u32);
                serializer.push_string(login);
                serializer.push_string(pass);
            }
            Request::UserRegster(login, pass) => {
                serializer.push_u32(RequestIds::UserRegster as u32);
                serializer.push_string(login);
                serializer.push_string(pass);
            }

            Request::SaveKeyForUser(uid, key) => {
                serializer.push_u32(RequestIds::SaveKeyForUser as u32);
                serializer.push_usize(*uid);
                serializer.push_data(key as &[u8]);
            }
            Request::GetKeyForUser(uid) => {
                serializer.push_u32(RequestIds::GetKeyForUser as u32);
                serializer.push_usize(*uid);
            }

            Request::AllocSlot() => {
                serializer.push_u32(RequestIds::AllocSlot as u32);
            }
            Request::SaveToSlot(slotid, data) => {
                serializer.push_u32(RequestIds::SaveToSlot as u32);
                serializer.push_usize(*slotid);
                serializer.push_data(data.as_slice());
            }
            Request::GetFromSlot(slotid) => {
                serializer.push_u32(RequestIds::GetFromSlot as u32);
                serializer.push_usize(*slotid);
            }
            Request::FreeSlot(slotid) => {
                serializer.push_u32(RequestIds::FreeSlot as u32);
                serializer.push_usize(*slotid);
            }

            Request::TpmLock(data, keyid, slotid) => {
                serializer.push_u32(RequestIds::TpmLock as u32);
                serializer.push_data(data.as_slice());
                serializer.push_usize(*keyid);
                serializer.push_usize(*slotid);
            }
            Request::TpmUnlock(data, keyid, slotid) => {
                serializer.push_u32(RequestIds::TpmUnlock as u32);
                serializer.push_data(data.as_slice());
                serializer.push_usize(*keyid);
                serializer.push_usize(*slotid);
            }
        }

        serializer
    }
}

impl TryInto<RequestIds> for u32 {
    type Error = crate::error::Error;
    fn try_into(self) -> Result<RequestIds, Self::Error> {
        match self {
            x if x == RequestIds::UserLogin as u32 => Ok(RequestIds::UserLogin),
            x if x == RequestIds::UserRegster as u32 => Ok(RequestIds::UserRegster),
            x if x == RequestIds::SaveKeyForUser as u32 => Ok(RequestIds::SaveKeyForUser),
            x if x == RequestIds::GetKeyForUser as u32 => Ok(RequestIds::GetKeyForUser),
            x if x == RequestIds::AllocSlot as u32 => Ok(RequestIds::AllocSlot),
            x if x == RequestIds::SaveToSlot as u32 => Ok(RequestIds::SaveToSlot),
            x if x == RequestIds::GetFromSlot as u32 => Ok(RequestIds::GetFromSlot),
            x if x == RequestIds::FreeSlot as u32 => Ok(RequestIds::FreeSlot),
            x if x == RequestIds::TpmLock as u32 => Ok(RequestIds::TpmLock),
            x if x == RequestIds::TpmUnlock as u32 => Ok(RequestIds::TpmUnlock),
            _ => Err(Error::InvalidEnum)
        }
    }
}

impl Deserialize for Request {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, Error> where Self: Sized {
        let ty: RequestIds = deserializer.pop_u32()?.try_into()?;

        match ty {
            RequestIds::UserLogin => Ok(Request::UserLogin(deserializer.pop_string()?, deserializer.pop_string()?)),
            RequestIds::UserRegster => Ok(Request::UserRegster(deserializer.pop_string()?, deserializer.pop_string()?)),

            RequestIds::SaveKeyForUser => Ok(Request::SaveKeyForUser(deserializer.pop_usize()?, deserializer.pop_data()?.try_into().map_err(|_| Error::DeserializeEndOfInput)?)),
            RequestIds::GetKeyForUser => Ok(Request::GetKeyForUser(deserializer.pop_usize()?)),

            RequestIds::AllocSlot => Ok(Request::AllocSlot()),
            RequestIds::SaveToSlot => Ok(Request::SaveToSlot(deserializer.pop_usize()?, deserializer.pop_data()?)),
            RequestIds::GetFromSlot => Ok(Request::GetFromSlot(deserializer.pop_usize()?)),
            RequestIds::FreeSlot => Ok(Request::FreeSlot(deserializer.pop_usize()?)),

            RequestIds::TpmLock => Ok(Request::TpmLock(deserializer.pop_data()?, deserializer.pop_usize()?, deserializer.pop_usize()?)),
            RequestIds::TpmUnlock => Ok(Request::TpmUnlock(deserializer.pop_data()?, deserializer.pop_usize()?, deserializer.pop_usize()?))
        }
    }
}

pub(super) enum Response {
    Key(KeyType),
    Data(Vec<u8>),
    Id(usize),
    Ok,
    Err(Error)
}

enum ResponseId {
    Key = 1,
    Data = 2,
    Id = 3,
    Ok = 4,
    Err = 5
}

impl Serialize for Response {
    fn serialize(&self) -> Serializer {
        let mut serializer = Serializer::new();

        match self {
            Response::Ok => {
                serializer.push_u32(ResponseId::Ok as u32);
            }
            Response::Key(v) => {
                serializer.push_u32(ResponseId::Key as u32);
                serializer.push_data(v as &[u8]);
            }
            Response::Data(v) => {
                serializer.push_u32(ResponseId::Data as u32);
                serializer.push_data(v as &[u8]);
            }
            Response::Id(id) => {
                serializer.push_u32(ResponseId::Id as u32);
                serializer.push_usize(*id);
            }
            Response::Err(err) => {
                serializer.push_u32(ResponseId::Err as u32);
                serializer.push_u32(*err as u32);
            }
        }

        serializer
    }
}

impl TryInto<ResponseId> for u32 {
    type Error = Error;
    fn try_into(self) -> Result<ResponseId, Self::Error> {
        match self {
            x if x == ResponseId::Ok as u32 => Ok(ResponseId::Ok),
            x if x == ResponseId::Key as u32 => Ok(ResponseId::Key),
            x if x == ResponseId::Data as u32 => Ok(ResponseId::Data),
            x if x == ResponseId::Id as u32 => Ok(ResponseId::Id),
            x if x == ResponseId::Err as u32 => Ok(ResponseId::Err),

            _ => Err(Error::InvalidEnum)
        }
    }
}

impl Deserialize for Response {
    fn deserialize(deserializer: &mut Deserializer) -> Result<Self, Error> where Self: Sized {
        let ty: ResponseId = deserializer.pop_u32()?.try_into()?;

        match ty {
            ResponseId::Ok => Ok(Response::Ok),
            ResponseId::Id => Ok(Response::Id(deserializer.pop_usize()?)),
            ResponseId::Key => Ok(Response::Key(deserializer.pop_data()?.try_into().map_err(|_| Error::DeserializeEndOfInput)?)),
            ResponseId::Data => Ok(Response::Data(deserializer.pop_data()?)),
            ResponseId::Err => Ok(Response::Err(deserializer.pop_u32()?.try_into()?))
        }
    }
}

