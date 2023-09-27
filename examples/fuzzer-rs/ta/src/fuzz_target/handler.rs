use std::hash::Hash;
use std::string::String;
use std::vec::Vec;
use std::{collections::hash_map::HashMap, convert::TryInto};
use optee_utee::{trace_println, AttributeMemref, Digest};
use std::fmt::Write;

use crate::fuzzer;

use super::error::Error;
use super::request::*;
use super::serialize::*;

macro_rules! bugon {
    ($msg:expr, $val:expr) => {
        {
            if $val.is_none() {
                trace_println!("BUG [[{}]]", $msg);
            }
            $val
        }
    };
}

#[derive(Hash, Eq, PartialEq)]
pub struct UserData {
    pub user: String,
    pub pass: String,
}

#[derive(Hash, Eq, PartialEq, Debug)]
pub enum Attr {
    Str(String),
    Int(usize)
}

pub struct Handler {
    uid: HashMap<UserData, usize>,
    keys: HashMap<usize, KeyType>,
    slots: HashMap<usize, Vec<u8>>,
    data: HashMap<[u8; 32], Vec<u8>>,
    uids: usize,
    sids: usize,
    attrs: HashMap<usize, HashMap<String, Attr>>
}

impl Handler {
    pub fn new() -> Handler {
        let handler = Handler {
            uid: HashMap::new(),
            keys: HashMap::new(),
            slots: HashMap::new(),
            data: HashMap::new(),
            uids: 0usize,
            sids: 0usize,
            attrs: HashMap::new()
        };

        handler
    }

    fn hash(&self, data: &[u8]) -> [u8; 32] {
        let digets =
            Digest::allocate(optee_utee::AlgorithmId::Sha256).expect("Cannot allocate sha256");
        let mut ret = [0u8; 32];
        digets.do_final(data, &mut ret);
        ret
    }

    pub fn command(&mut self, req: Vec<u8>) -> Vec<u8> {
        let resp = if let Ok(req) = Request::deserialize(&mut Deserializer::new(req)) {
            self.handle(&req)
        } else {
            Response::Err(Error::DeserializeEndOfInput)
        };

        resp.serialize().into()
    }

    fn parse_user_attrs(storage: &mut HashMap<String, Attr>, attr: &String) {
        let mut i = 0;

        while i < attr.len() {
            if attr.as_bytes()[i] == '"' as u8 {
                let mut name = String::new();
                i += 1;
                while attr.as_bytes()[i] != '"' as u8 {
                    name.push(attr.as_bytes()[i].into());
                    i += 1;
                }
                i += 1; // "
                i += 1; // :
                if attr.as_bytes()[i]  == '"' as u8 {
                    let mut value = String::new();
                    i += 1;
                    while attr.as_bytes()[i]  != '"' as u8 {
                        value.push(attr.as_bytes()[i].into());
                        i += 1;
                    }
                    i += 1; // "
                    i += 1; // ,
                    storage.insert(name, Attr::Str(value));
                } else {
                    let mut value = String::new();
                    i += 1;
                    while attr.as_bytes()[i]  != ',' as u8 {
                        value.push(attr.as_bytes()[i].into());
                        i += 1;
                    }
                    i += 1; // ','
                    if let Ok(v) = value.parse::<usize>() {
                        storage.insert(name, Attr::Int(v));
                    }
                }
            }
        }
    }

    pub fn handle(&mut self, request: &Request) -> Response {
        match request {
            Request::UserLogin(user, pass) => {
                let user = UserData {
                    user: user.clone(),
                    pass: pass.clone(),
                };
                let entry = self.uid.get(&user);

                match entry {
                    Some(id) => Response::Id(*id),
                    None => Response::Err(Error::InvalidCredentials),
                }
            }
            Request::UserRegister(user, pass) => {
                let user = UserData {
                    user: user.clone(),
                    pass: pass.clone(),
                };
                self.uid.insert(user, self.uids);
                let id = self.uids;
                self.uids += 1;

                Response::Id(id)
            }
            Request::SetUserAttributes(uid, attr) => {
                let entry = self.attrs.entry(*uid)
                    .or_insert(HashMap::new());
                entry.clear();
                Self::parse_user_attrs(entry, attr);
                Response::Ok
            }
            Request::GetUserAttributes(uid) => {
                if let Some(attr) = self.attrs.get(uid) {
                    trace_println!("{:?}\n", attr);
                } else {
                    trace_println!("No attrs for user\n");
                }

                Response::Ok
            }

            Request::GetKeyForUser(uid) => {
                if let Some(key) = self.keys.get(uid) {
                    Response::Key(key.clone())
                } else {
                    Response::Err(Error::NoSuchKey)
                }
            }
            Request::SaveKeyForUser(uid, key) => {
                self.keys.insert(*uid, key.clone());
                Response::Ok
            }

            Request::AllocSlot() => {
                self.slots.insert(self.sids, Vec::new());
                let id = self.sids;
                self.sids += 1;
                Response::Id(id)
            }
            Request::SaveToSlot(id, data) => {
                *bugon!("SaveToSlot", self.slots.get_mut(id))
                    .unwrap() = data.to_owned();
                Response::Ok
            }
            Request::GetFromSlot(id) => Response::Data(self.slots.get(id).unwrap().to_owned()),
            Request::SetupSlot(slotid, flags, size) => {
                let slot = self.slots.get_mut(slotid);

                if let Some(slot) = slot {
                    if *flags == 0xDEADBEEF {
                        slot.resize(*size, 0u8);
                        return Response::Ok;
                    }
                }

                Response::Err(Error::InvalidResponse)
            }
            Request::FreeSlot(id) => {
                self.slots.remove(id);
                Response::Ok
            }

            Request::TpmLock(data, uid, slotid) => {
                let hash = self.hash(&data);
                let mut mac = Vec::new();
                mac.extend(hash.iter());
                mac.extend(bugon!("TpmLock no key", self.keys.get(uid)).expect("Failed to get user key"));
                let id = self.hash(mac.as_slice());

                if !self.slots.contains_key(slotid) {
                    return Response::Err(Error::NoSuchKey);
                }

                self.data.insert(
                    id,
                    bugon!("TpmLock no slot", self.slots
                        .get(slotid))
                        .expect("Failed to get slot")
                        .to_owned(),
                );
                Response::Ok
            }
            Request::TpmUnlock(data, uid, slotid) => {
                let hash = self.hash(&data);
                let mut mac = Vec::new();
                mac.extend(hash.iter());
                mac.extend(bugon!("TpmUnlock no key", self.keys.get(uid)).expect("Failed to get user key"));
                let id = self.hash(mac.as_slice());

                if !self.slots.contains_key(slotid) {
                    return Response::Err(Error::NoSuchKey);
                }

                *bugon!("TpmUnlock no slot", self.slots.get_mut(slotid)).unwrap() = bugon!("TpmUnlock no data", self.data.get(&id)).unwrap().to_owned();

                Response::Ok
            }
        }
    }
}
