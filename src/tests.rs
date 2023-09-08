use crate::*;

#[test]
fn test_serialize() {
    let example_data = b"some data";
    let password = b"password";
    let encrypted = serialize(example_data, password).unwrap();
    assert_ne!(example_data.to_vec(), encrypted);
    assert!(is_encrypted(&encrypted).unwrap());
    assert_eq!(example_data.to_vec(), deserialize(&encrypted, password).unwrap());
    assert_ne!(example_data.to_vec(), deserialize(&encrypted, b"bacPass").unwrap());
}

#[test]
fn test_serialize_no_pass() {
    let example_data = b"some data";
    let encoded = serialize_no_pass(example_data);
    assert!(!is_encrypted(&encoded).unwrap());
    assert_eq!(example_data.to_vec(), deserialize_no_pass(&encoded).unwrap());
    assert_eq!(example_data.to_vec(), deserialize(&encoded, b"sadas").unwrap());
}

#[cfg(feature = "serde")]
mod serde_tests {
    use super::*;
    use serde::{Serialize, Deserialize};
    
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct ExampleStruct {
        data: i32,
        more_data: Vec<u8>,
    }
    
    #[test]
    fn serde_serialize() {
        let example_data = ExampleStruct{ data: 16, more_data: vec![5,2,41,2] };
        let password = b"password";
        let encrypted = serialize_serde(&example_data, password).unwrap();
        assert!(is_encrypted(&encrypted).unwrap());
        assert_eq!(example_data, deserialize_serde(&encrypted, password).unwrap());
        assert!(deserialize_serde::<ExampleStruct>(&encrypted, b"bacPass").is_err());
    }
    
    #[test]
    fn serde_serialize_no_pass() {
        let example_data = ExampleStruct{ data: 16, more_data: vec![5,2,41,2] };
        let encoded = serialize_serde_no_pass(&example_data).unwrap();
        assert!(!is_encrypted(&encoded).unwrap());
        assert_eq!(example_data, deserialize_serde_no_pass(&encoded).unwrap());
        assert_eq!(example_data, deserialize_serde(&encoded, b"asdhas").unwrap());
    }
}
