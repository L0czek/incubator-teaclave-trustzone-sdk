use std::convert::TryInto;

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub(super) enum Error {
    InvalidCredentials = 1,
    NoSuchKey = 2,
    InvalidEnum = 3,
    DeserializeEndOfInput = 4,
    InvalidResponse = 5,
}

impl TryInto<Error> for u32 {
    type Error = Error;
    fn try_into(self) -> Result<Error, Self::Error> {
        match self {
            x if x == Error::InvalidCredentials as u32 => Ok(Error::InvalidCredentials),
            x if x == Error::NoSuchKey as u32 => Ok(Error::NoSuchKey),
            x if x == Error::InvalidEnum as u32 => Ok(Error::InvalidEnum),
            x if x == Error::DeserializeEndOfInput as u32 => Ok(Error::DeserializeEndOfInput),
            x if x == Error::InvalidResponse as u32 => Ok(Error::InvalidResponse),

            _ => Err(Error::InvalidEnum)
        }

    }
}
