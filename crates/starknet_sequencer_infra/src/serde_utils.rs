use std::fmt::Debug;

use bincode::{deserialize, serialize};
use serde::{Deserialize, Serialize};

#[cfg(test)]
#[path = "serde_utils_test.rs"]
pub mod serde_utils_test;

// A generic wrapper struct for binary serialization and deserialization, used for remote component
// communication.
#[derive(Serialize, Deserialize, Debug)]
pub struct SerdeWrapper<T> {
    data: T,
}

impl<T> SerdeWrapper<T>
where
    T: Serialize + for<'de> Deserialize<'de> + Debug,
{
    pub fn new(data: T) -> Self {
        Self { data }
    }

    pub fn wrapper_serialize(&self) -> Result<Vec<u8>, bincode::Error> {
        serialize(self)
    }

    pub fn wrapper_deserialize(bytes: &[u8]) -> Result<T, bincode::Error> {
        deserialize(bytes).map(|serde_wrapper: Self| serde_wrapper.data)
    }
}
