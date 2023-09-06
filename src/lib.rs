use std::fmt::Display;
use argon2::Argon2;
use libaes::{AES_256_KEY_LEN, Cipher};

const IV_SIZE: usize = 16;
const SALT: &'static [u8] = b"WvgoXslnFkE0qM!R#gVONUCzVk2BeT!lSQ3$qnMLJ6q5dTbB3RrXRERlV2qAc%XMrN#A5f3P3W&!HUvznbqIFTnS3OdyYu3&lzEvLjItAamR8JN8wjR%Y0MPpzfE3ha7";

#[inline]
fn compute_key_and_nonce(password: &[u8]) -> ([u8; AES_256_KEY_LEN], [u8; IV_SIZE]) {
    let mut dig = vec![0; AES_256_KEY_LEN + IV_SIZE];
    let mut key = [0; AES_256_KEY_LEN];
    let mut iv = [0; IV_SIZE];
    Argon2::default().hash_password_into(password, SALT, &mut dig).unwrap();
    dig.iter().take(AES_256_KEY_LEN).enumerate().for_each(|(i, v)| key[i] = *v);
    dig.into_iter().skip(AES_256_KEY_LEN).enumerate().for_each(|(i, v)| iv[i] = v);
    (key, iv)
}

#[inline]
pub fn serialize(data: &[u8], password: &[u8]) -> Vec<u8> {
    let (key, iv) = compute_key_and_nonce(password);
    let mut ans = vec![1];
    ans.append(&mut Cipher::new_256(&key).cbc_encrypt(&iv, data));
    ans
}

#[inline]
pub fn serialize_no_pass(data: &[u8]) -> Vec<u8> {
    let mut ans = vec![0];
    ans.extend(data.into_iter());
    ans
}

#[inline]
pub fn deserialize(data: &[u8], password: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Err(Error::DataIsEmpty);
    }
    if data[0] == 0 {
        return Ok(data[1..].to_vec());
    }
    let (key, iv) = compute_key_and_nonce(password);
    Ok(
        std::panic::catch_unwind(|| {
            Cipher::new_256(&key).cbc_decrypt(&iv, &data[1..])
        }).map_err(|_| Error::WrondPassword)?
    )
}

#[inline]
pub fn deserialize_no_pass(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.is_empty() {
        return Err(Error::DataIsEmpty);
    }
    if data[0] == 0 {
        return Ok(data[1..].to_vec());
    }
    Err(Error::DataIsEncrypted)
}

#[inline]
pub fn is_encrypted(data: &[u8]) -> Result<bool, Error> {
    if data.is_empty() {
        return Err(Error::DataIsEmpty);
    }
    Ok(data[0] == 1)
}

#[cfg(feature = "serde")]
use rmp_serde::encode::Error as EncodeError;
#[cfg(feature = "serde")]
use rmp_serde::decode::Error as DecodeError;
#[derive(Debug)]
pub enum Error {
    DataIsEncrypted,
    DataIsEmpty,
    WrondPassword,
    #[cfg(feature = "serde")]
    SerdeEncodingError(EncodeError),
    #[cfg(feature = "serde")]
    SerdeDecodingError(DecodeError),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::DataIsEncrypted => "DataIsEncrypted".to_owned(),
            Self::DataIsEmpty => "DataIsEmpty".to_owned(),
            Self::WrondPassword => "WrondPassword".to_owned(),
            #[cfg(feature = "serde")]
            Self::SerdeEncodingError(err) => err.to_string(),
            #[cfg(feature = "serde")]
            Self::SerdeDecodingError(err) => err.to_string(),
        })
    }
}

impl std::error::Error for Error { }

#[cfg(feature = "serde")]
mod serde_feature {
    use serde::{Serialize, Deserialize};
    use super::*;
    
    impl From<EncodeError> for Error {
        fn from(value: EncodeError) -> Self {
            Self::SerdeEncodingError(value)
        }
    }
    
    impl From<DecodeError> for Error {
        fn from(value: DecodeError) -> Self {
            Self::SerdeDecodingError(value)
        }
    }
   
    #[inline] 
    pub fn serialize_serde<T: Serialize>(data: &T, password: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(serialize(&rmp_serde::to_vec(data)?, password))
    }

    #[inline]
    pub fn deserialize_serde<T: for<'a> Deserialize<'a>>(data: &[u8], password: &[u8]) -> Result<T, Error> {
        Ok(rmp_serde::from_slice(&deserialize(data, password)?)?)
    }
   
    #[inline] 
    pub fn serialize_serde_no_pass<T: Serialize>(data: &T) -> Result<Vec<u8>, Error> {
        Ok(serialize_no_pass(&rmp_serde::to_vec(data)?))
    }

    #[inline]
    pub fn deserialize_serde_no_pass<T: for<'a> Deserialize<'a>>(data: &[u8]) -> Result<T, Error> {
        Ok(rmp_serde::from_slice(&deserialize_no_pass(data)?)?)
    }
}

#[cfg(feature = "serde")]
pub use serde_feature::*;

#[cfg(test)]
mod tests;
