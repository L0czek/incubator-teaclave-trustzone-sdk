use std::hash::Hash;
use std::string::String;
use std::vec::Vec;
use std::{collections::hash_map::HashMap, convert::TryInto};

use optee_utee::{trace_println, AttributeMemref, Digest};

use super::error::Error;
use super::request::*;
use super::serialize::*;

#[derive(Hash, Eq, PartialEq)]
pub struct UserData {
    pub user: String,
    pub pass: String,
}

pub struct Handler {
    uid: HashMap<UserData, usize>,
    keys: HashMap<usize, KeyType>,
    slots: HashMap<usize, Vec<u8>>,
    data: HashMap<[u8; 32], Vec<u8>>,
    uids: usize,
    sids: usize,
}

impl Handler {
    pub fn new() -> Handler {
        Handler {
            uid: HashMap::new(),
            keys: HashMap::new(),
            slots: HashMap::new(),
            data: HashMap::new(),
            uids: 0usize,
            sids: 0usize,
        }
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
                *self.slots.get_mut(id).unwrap() = data.to_owned();
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
                mac.extend(self.keys.get(uid).expect("Failed to get user key"));
                let id = self.hash(mac.as_slice());
                self.data.insert(
                    id,
                    self.slots
                        .get(slotid)
                        .expect("Failed to get slot")
                        .to_owned(),
                );
                Response::Ok
            }
            Request::TpmUnlock(data, uid, slotid) => {
                let hash = self.hash(&data);
                let mut mac = Vec::new();
                mac.extend(hash.iter());
                mac.extend(self.keys.get(uid).expect("Failed to get user key"));
                let id = self.hash(mac.as_slice());
                *self.slots.get_mut(slotid).unwrap() = self.data.get(&id).unwrap().to_owned();

                Response::Ok
            }
        }
    }
}
