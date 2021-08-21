use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("DID resolution failed.")]
    DidResolutionFailed,

    #[cfg(feature = "jolo")]
    #[error("Only correct did:jolo: URLs are supported")]
    NotDidJolo,

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

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[cfg(feature = "jolo")]
    #[error("Not ETH address. Length must be 20 bytes")]
    NotEthAddress,

    #[cfg(feature = "jolo")]
    #[error(transparent)]
    W3Error(#[from] web3::Error),

    #[cfg(feature = "jolo")]
    #[error(transparent)]
    W3EthError(#[from] web3::ethabi::Error),

    #[cfg(feature = "jolo")]
    #[error(transparent)]
    W3ContractError(#[from] web3::contract::Error),

    #[cfg(feature = "jolo")]
    #[error(transparent)]
    FromHexError(#[from] hex::FromHexError),

    #[cfg(feature = "jolo")]
    #[error("IPFS response error: {0}")]
    IpfsResponseError(String),

    #[error(transparent)]
    FromUtf8Error(#[from] std::string::FromUtf8Error),

    #[cfg(feature = "jolo")]
    #[error("Failed to parse IPFS http url: {0}")]
    UriParseError(String),
}
