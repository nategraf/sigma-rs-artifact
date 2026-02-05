use std::fmt::Display;

use crate::{exceptions::OoniErr, OoniResult};
use base64::prelude::*;
use pyo3::{prelude::*, types::PyString};

pub fn to_pystring<T: serde::Serialize>(py: Python<'_>, value: &T) -> Py<PyString> {
    // We consider a bad serialization as a programming error since most of the times
    // we want to serialize a structure made by us that should be well-formed
    let bytes =
        bincode::serialize(&value).unwrap_or_else(|e| panic!("Could not serialize value: {e}"));
    PyString::new(py, &BASE64_STANDARD.encode(bytes)).into()
}

pub fn from_pystring<T: serde::de::DeserializeOwned>(
    py: Python<'_>,
    py_string: &Py<PyString>,
) -> OoniResult<T> {
    // We consider bad deserialization an user error, since most of the time
    // what we are deserializing comes from the user in python world
    let s = to_dser_err(py_string.to_str(py))?;
    let bytes = to_dser_err(BASE64_STANDARD.decode(s))?;
    let result = bincode::deserialize::<T>(bytes.as_ref());
    to_dser_err(result)
}

fn to_dser_err<T, E: Display>(x: Result<T, E>) -> Result<T, OoniErr> {
    x.map_err(|e| OoniErr::DeserializationFailed {
        reason: e.to_string(),
    })
}
