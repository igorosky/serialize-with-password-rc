//! # Serialize_with_password
//! Small crate that adds additional layer on top of the serde crate. This crate allows to encrypt serialized data with password
//! 
//! # Examples
//! ## Serialization with password
//! ```
//! use serialize_with_password::{serialize, is_encrypted, deserialize};
//! 
//! let example_data = b"some data";
//! let password = b"password";
//! let encrypted = serialize(example_data, password).unwrap();
//! 
//! assert_ne!(example_data.to_vec(), encrypted);
//! assert!(is_encrypted(&encrypted).expect("Correctly encrypted data always will return Ok(bool) for is_encrypted"));
//! assert_eq!(example_data.to_vec(), deserialize(&encrypted, password).expect("Correct password"));
//! assert!(deserialize(&encrypted, b"bacPass").is_err());
//! ```
//! 
//! ## Serialize without password
//! ```
//! use serialize_with_password::{serialize_no_pass, is_encrypted, deserialize, deserialize_no_pass};
//! 
//! let example_data = b"some data";
//! let encoded = serialize_no_pass(example_data);
//! 
//! assert!(!is_encrypted(&encoded).unwrap());
//! assert_eq!(example_data.to_vec(), deserialize_no_pass(&encoded).unwrap());
//! assert_eq!(example_data.to_vec(), deserialize(&encoded, b"Any password").unwrap());
//! ```

extern crate chacha20poly1305;
extern crate argon2;

use chacha20poly1305::{aead::Aead, XChaCha20Poly1305, Key, KeyInit};
pub use chacha20poly1305::Error as ChaCha20Error;
pub use argon2::Error as Argon2Error;

#[cfg(feature = "serde")]
pub use rmp_serde::encode::Error as EncodeError;
#[cfg(feature = "serde")]
pub use rmp_serde::decode::Error as DecodeError;

#[derive(Debug)]
pub enum Error {
    DataIsEncrypted,
    DataIsEmpty,
    Argon2Error(Argon2Error),
    ChaCha20Error(ChaCha20Error),
    #[cfg(feature = "serde")]
    SerdeEncodingError(EncodeError),
    #[cfg(feature = "serde")]
    SerdeDecodingError(DecodeError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", match self {
            Self::DataIsEncrypted => "DataIsEncrypted".to_owned(),
            Self::DataIsEmpty => "DataIsEmpty".to_owned(),
            Self::Argon2Error(err) => err.to_string(),
            Self::ChaCha20Error(err) => err.to_string(),
            #[cfg(feature = "serde")]
            Self::SerdeEncodingError(err) => err.to_string(),
            #[cfg(feature = "serde")]
            Self::SerdeDecodingError(err) => err.to_string(),
        })
    }
}

impl From<Argon2Error> for Error {
    fn from(value: Argon2Error) -> Self {
        Self::Argon2Error(value)
    }
}

impl From<ChaCha20Error> for Error {
    fn from(value: ChaCha20Error) -> Self {
        Self::ChaCha20Error(value)
    }
}

impl std::error::Error for Error { }

pub type Result<T> = core::result::Result<T, Error>;

const SYMMETRIC_KEY_SIZE: usize = 32;
const SYMMETRIC_NONE_SIZE: usize = 24;
const SALT: &'static [u8] = b"WvgoXslnFkE0qM!R#gVONUCzVk2BeT!lSQ3$qnMLJ6q5dTbB3RrXRERlV2qAc%XMrN#A5f3P3W&!HUvznbqIFTnS3OdyYu3&lzEvLjItAamR8JN8wjR%Y0MPpzfE3ha7";

#[inline]
fn compute_key_and_nonce(password: &[u8]) -> core::result::Result<(Key, [u8; SYMMETRIC_NONE_SIZE]), Argon2Error> {
    let mut dig = vec![0; SYMMETRIC_KEY_SIZE + SYMMETRIC_NONE_SIZE];
    let mut key = [0; SYMMETRIC_KEY_SIZE];
    let mut iv = [0; SYMMETRIC_NONE_SIZE];
    argon2::Argon2::default().hash_password_into(password, SALT, &mut dig)?;
    dig.iter().take(SYMMETRIC_KEY_SIZE).enumerate().for_each(|(i, v)| key[i] = *v);
    dig.into_iter().skip(SYMMETRIC_KEY_SIZE).enumerate().for_each(|(i, v)| iv[i] = v);
    Ok((Key::from(key), iv))
}

/// Encrypt data using password
/// 
/// # Example
/// ```
/// use serialize_with_password::{serialize, is_encrypted, deserialize, deserialize_no_pass};
/// 
/// let example_data = b"some data";
/// let password = b"password";
/// let encrypted = serialize(example_data, password).unwrap();
/// 
/// assert!(is_encrypted(&encrypted).expect("Data is encrypted correctly"));
/// assert_ne!(example_data.to_vec(), encrypted);
/// assert_eq!(example_data.to_vec(), deserialize(&encrypted, password).expect("Correct password"));
/// assert!(deserialize(&encrypted, b"bacPass").is_err());
/// assert!(deserialize_no_pass(&encrypted).is_err());
/// ```
#[inline]
pub fn serialize(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    let (key, nonce) = compute_key_and_nonce(password)?;
    let mut ans = vec![1];
    ans.append(&mut XChaCha20Poly1305::new(&key).encrypt(&nonce.into(), data)?);
    Ok(ans)
}

/// Serialize data without password
/// 
/// # Example
/// ```
/// use serialize_with_password::{serialize_no_pass, is_encrypted, deserialize, deserialize_no_pass};
/// 
/// let example_data = b"some data";
/// let encoded = serialize_no_pass(example_data);
/// 
/// assert!(!is_encrypted(&encoded).expect("Data is encrypted correctly"));
/// assert_eq!(example_data.to_vec(), deserialize_no_pass(&encoded).expect("Correctly serialized data will always return Ok(_)"));
/// assert_eq!(example_data.to_vec(), deserialize(&encoded, b"any string of bytes").expect("Data serialized without password can be deserialized with any password"));
/// ```
#[inline]
pub fn serialize_no_pass(data: &[u8]) -> Vec<u8> {
    let mut ans = vec![0];
    ans.extend(data.into_iter());
    ans
}


/// Decrypt data with given password
/// 
/// # Error
///  - if `data` slice is empty (Error::DataIsEmpty)
///  - if `argon2` hasgin function return Error (Error::Argon2Error(Argon2Error))
///  - if `password` is incorrect (Error::ChaCha20Error(ChaCha20Error))
/// 
/// # Example
/// ```
/// use serialize_with_password::{serialize, serialize_no_pass, is_encrypted, deserialize};
/// 
/// let example_data = b"some data";
/// let encoded = serialize_no_pass(example_data);
/// let password = b"password";
/// let encrypted = serialize(example_data, password).unwrap();
/// 
/// assert!(!is_encrypted(&encoded).expect("Data is encrypted correctly"));
/// assert!(is_encrypted(&encrypted).expect("Data is encrypted correctly"));
/// assert_eq!(example_data.to_vec(), deserialize(&encoded, b"any string of bytes").expect("Data serialized without password can be deserialized with any password"));
/// assert_eq!(example_data.to_vec(), deserialize(&encrypted, password).expect("Correct password"));
/// assert!(deserialize(&encrypted, b"Wrong password").is_err());
/// ```
#[inline]
pub fn deserialize(data: &[u8], password: &[u8]) -> Result<Vec<u8>> {
    if data.is_empty() {
        return Err(Error::DataIsEmpty);
    }
    if data[0] == 0 {
        return Ok(data[1..].to_vec());
    }
    let (key, nonce) = compute_key_and_nonce(password)?;
    Ok(XChaCha20Poly1305::new(&key).decrypt(&nonce.into(), &data[1..])?)
}

/// Deserialize data
/// 
/// # Error
///  - if `data` slice is empty (Error::DataIsEmpty)
///  - if `data` is encrypted (Error::DataIsEncrypted)
/// 
/// # Example
/// ```
/// use serialize_with_password::{serialize, is_encrypted, serialize_no_pass, deserialize_no_pass};
/// 
/// let example_data = b"some data";
/// let encoded = serialize_no_pass(example_data);
/// let password = b"password";
/// let encrypted = serialize(example_data, password).unwrap();
/// 
/// assert!(!is_encrypted(&encoded).expect("Data is encrypted correctly"));
/// assert!(is_encrypted(&encrypted).expect("Data is encrypted correctly"));
/// assert_eq!(example_data.to_vec(), deserialize_no_pass(&encoded).expect("Data is serialized correctly"));
/// assert!(deserialize_no_pass(&encrypted).is_err());
/// assert!(deserialize_no_pass(&encrypted).is_err());
/// ```
#[inline]
pub fn deserialize_no_pass(data: &[u8]) -> Result<Vec<u8>> {
    if !is_encrypted(data)? {
        return Ok(data[1..].to_vec());
    }
    Err(Error::DataIsEncrypted)
}

/// Returns whether data is encrypted
/// For random non empty data returns random bool value
/// 
/// # Error
/// Only if data is empty (Error::DataIsEmpty)
/// 
/// # Example
/// ```
/// use serialize_with_password::{serialize, serialize_no_pass, is_encrypted, deserialize_no_pass};
/// 
/// let example_data = b"some data";
/// let encoded = serialize_no_pass(example_data);
/// let password = b"password";
/// let encrypted = serialize(example_data, password).unwrap();
/// 
/// assert!(!is_encrypted(&encoded).expect("Data is encoded correctly"));
/// assert!(is_encrypted(&encrypted).expect("Data is encrypted correctly"));
/// assert!(is_encrypted(&Vec::new()).is_err());
/// ```
#[inline]
pub fn is_encrypted(data: &[u8]) -> Result<bool> {
    if data.is_empty() {
        return Err(Error::DataIsEmpty);
    }
    Ok(data[0] == 1)
}

#[cfg(feature = "serde")]
mod serde_feature {
    //! bbbb# Examples
    //! 
    //! ## Serialize serde with password
    //! 
    //! ```
    //! use serde::{Serialize, Deserialize};
    //! use serialize_with_password::{serialize_serde, is_encrypted, deserialize_serde};
    //! 
    //! #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    //! struct ExampleStruct {
    //!     data: i32,
    //!     more_data: Vec<u8>,
    //! }
    //! 
    //! let example_data = ExampleStruct{ data: 16, more_data: vec![5,2,41,2] };
    //! let password = b"password";
    //! let encrypted = serialize_serde(&example_data, password).unwrap();
    //! assert!(is_encrypted(&encrypted).unwrap());
    //! assert_eq!(example_data, deserialize_serde(&encrypted, password).unwrap());
    //! assert!(deserialize_serde::<ExampleStruct>(&encrypted, b"bacPass").is_err());
    //! ```
    //! 
    //! ## Serialize serde without password
    //! 
    //! ```
    //! use serde::{Serialize, Deserialize};
    //! use serialize_with_password::{serialize_serde_no_pass, is_encrypted, deserialize_serde, deserialize_serde_no_pass};
    //! 
    //! #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    //! struct ExampleStruct {
    //!     data: i32,
    //!     more_data: Vec<u8>,
    //! }
    //! 
    //! let example_data = ExampleStruct{ data: 16, more_data: vec![5,2,41,2] };
    //! let encoded = serialize_serde_no_pass(&example_data).unwrap();
    //! assert!(!is_encrypted(&encoded).unwrap());
    //! assert_eq!(example_data, deserialize_serde_no_pass(&encoded).unwrap());
    //! assert_eq!(example_data, deserialize_serde(&encoded, b"asdhas").unwrap());
    //! ```

    extern crate serde;
    extern crate rmp_serde;
    
    pub use serde::{Serialize, Deserialize};
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
   
    /// Serialize data with serde then encrypt it
    /// 
    /// # Example
    /// ```
    /// use serde::{Serialize, Deserialize};
    /// use serialize_with_password::{serialize_serde, is_encrypted, deserialize_serde, deserialize_serde_no_pass};
    /// 
    /// #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    /// struct ExampleStruct {
    ///     data: i32,
    ///     more_data: Vec<u8>,
    /// }
    /// 
    /// let example_data = ExampleStruct{ data: 16, more_data: vec![5,2,41,2] };
    /// let password = b"password";
    /// let encrypted = serialize_serde(&example_data, password).unwrap();
    /// 
    /// assert!(is_encrypted(&encrypted).expect("Data is encrypted correctly"));
    /// assert_eq!(example_data, deserialize_serde(&encrypted, password).unwrap());
    /// assert!(deserialize_serde::<ExampleStruct>(&encrypted, b"badPass").is_err());
    /// assert!(deserialize_serde_no_pass::<ExampleStruct>(&encrypted).is_err());
    /// ```
    #[inline] 
    pub fn serialize_serde<T: Serialize>(data: &T, password: &[u8]) -> Result<Vec<u8>> {
        Ok(serialize(&rmp_serde::to_vec(data)?, password)?)
    }
    
    /// Serialize data with serde
    /// 
    /// # Example
    /// ```
    /// use serde::{Serialize, Deserialize};
    /// use serialize_with_password::{serialize_serde_no_pass, is_encrypted, deserialize_serde, deserialize_serde_no_pass};
    /// 
    /// #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    /// struct ExampleStruct {
    ///     data: i32,
    ///     more_data: Vec<u8>,
    /// }
    /// 
    /// let example_data = ExampleStruct{ data: 16, more_data: vec![5,2,41,2] };
    /// let encoded = serialize_serde_no_pass(&example_data).unwrap();
    /// 
    /// assert!(!is_encrypted(&encoded).expect("Data is encrypted correctly"));
    /// assert_eq!(example_data, deserialize_serde_no_pass(&encoded).unwrap());
    /// assert_eq!(example_data, deserialize_serde(&encoded, b"Any password").unwrap());
    /// ```
    #[inline] 
    pub fn serialize_serde_no_pass<T: Serialize>(data: &T) -> Result<Vec<u8>> {
        Ok(serialize_no_pass(&rmp_serde::to_vec(data)?))
    }

    /// Decrypt data and deserialize it with serde
    /// 
    /// # Example
    /// ```
    /// use serde::{Serialize, Deserialize};
    /// use serialize_with_password::{serialize_serde, serialize_serde_no_pass, is_encrypted, deserialize_serde};
    /// 
    /// #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    /// struct ExampleStruct {
    ///     data: i32,
    ///     more_data: Vec<u8>,
    /// }
    /// 
    /// let example_data = ExampleStruct{ data: 16, more_data: vec![5,2,41,2] };
    /// let encoded = serialize_serde_no_pass(&example_data).unwrap();
    /// let password = b"password";
    /// let encrypted = serialize_serde(&example_data, password).unwrap();
    /// 
    /// assert!(!is_encrypted(&encoded).expect("Data is encoded correctly"));
    /// assert!(is_encrypted(&encrypted).expect("Data is encrypted correctly"));
    /// assert_eq!(example_data, deserialize_serde(&encoded, b"Any password").unwrap());
    /// assert_eq!(example_data, deserialize_serde(&encrypted, password).unwrap());
    /// assert!(deserialize_serde::<ExampleStruct>(&encrypted, b"badPass").is_err());
    /// ```
    #[inline]
    pub fn deserialize_serde<T: for<'a> Deserialize<'a>>(data: &[u8], password: &[u8]) -> Result<T> {
        Ok(rmp_serde::from_slice(&deserialize(data, password)?)?)
    }

    /// Deserialize data with serde
    /// 
    /// # Example
    /// ```
    /// use serde::{Serialize, Deserialize};
    /// use serialize_with_password::{serialize_serde, serialize_serde_no_pass, is_encrypted, deserialize_serde_no_pass};
    /// 
    /// #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    /// struct ExampleStruct {
    ///     data: i32,
    ///     more_data: Vec<u8>,
    /// }
    /// 
    /// let example_data = ExampleStruct{ data: 16, more_data: vec![5,2,41,2] };
    /// let encoded = serialize_serde_no_pass(&example_data).unwrap();
    /// let password = b"password";
    /// let encrypted = serialize_serde(&example_data, password).unwrap();
    /// 
    /// assert!(!is_encrypted(&encoded).expect("Data is encoded correctly"));
    /// assert!(is_encrypted(&encrypted).expect("Data is encrypted correctly"));
    /// assert_eq!(example_data, deserialize_serde_no_pass(&encoded).unwrap());
    /// assert!(deserialize_serde_no_pass::<ExampleStruct>(&encrypted).is_err());
    /// ```
    #[inline]
    pub fn deserialize_serde_no_pass<T: for<'a> Deserialize<'a>>(data: &[u8]) -> Result<T> {
        Ok(rmp_serde::from_slice(&deserialize_no_pass(data)?)?)
    }
}

#[cfg(feature = "serde")]
pub use serde_feature::*;
