use cmz::CMZError;
use ooniauth_core::errors;
use pyo3::exceptions::PyException;
use pyo3::PyErr;
use pyo3_stub_gen::create_exception;
use thiserror::Error;

// Python excepions: This is what the user sees from the python side when running into an error

// Note that the module name must be the name of the pyproject module name to prevent errors,
// we should create an issue in the pyo3_stub_gen repo about this. The thing is that
// if the value of the module argument here is different of the pyproject one except for
// _ and -, it confuses itself and thinks that its a different module while writing in
// the same resulting .pyi, deleting parts of the content

create_exception! {
    ooniauth-py,
    ProtocolError,
    PyException,
    "An error performing the protocol"
}

create_exception! {
    ooniauth-py,
    DeserializationFailed,
    PyException,
    "An error trying to deserialize a binary buffer"
}

// TODO Q: should I create a new python exception per variant of errors::CredentialError?
create_exception! {
    ooniauth-py,
    CredentialError,
    PyException,
    "An authentication error"
}

// The following errors are useful to map rust errors to their corresponding python exceptions
// defined above

#[derive(Debug, Error)]
pub enum OoniErr {
    #[error("Protocol Error: {reason}")]
    ProtocolError { reason: CMZError },

    #[error("Credential Error: {reason}")]
    CredentialError { reason: errors::CredentialError },

    #[error("Deserialization Error: {reason}")]
    DeserializationFailed { reason: String },
}

pub type OoniResult<T> = Result<T, OoniErr>;

impl From<OoniErr> for PyErr {
    fn from(value: OoniErr) -> Self {
        // This function maps from rust error enums to their corresponding python exception
        match value {
            OoniErr::ProtocolError { reason } => ProtocolError::new_err(format!("{reason}")),
            OoniErr::DeserializationFailed { reason } => DeserializationFailed::new_err(reason),
            OoniErr::CredentialError {
                reason: errors::CredentialError::CMZError(e),
            } => ProtocolError::new_err(format!("{e}")),
            OoniErr::CredentialError { reason } => CredentialError::new_err(format!("{reason}")),
        }
    }
}

impl From<CMZError> for OoniErr {
    fn from(value: CMZError) -> Self {
        OoniErr::ProtocolError { reason: value }
    }
}

impl From<errors::CredentialError> for OoniErr {
    fn from(value: errors::CredentialError) -> Self {
        OoniErr::CredentialError { reason: value }
    }
}
