use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("did_key error: {0}")]
    DidKeyError(String),
    #[error("did_keri error: {0}")]
    DidKeriError(String),
    #[error("config file opening error: {0}")]
    ConfigOpenError(String),
    #[error(transparent)]
    Base64DecodeError(#[from]base64_url::base64::DecodeError),
    #[error(transparent)]
    SerdeError(#[from]serde_json::Error),
}
