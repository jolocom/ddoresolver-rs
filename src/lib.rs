pub mod error;

#[cfg(feature = "jolo")]
pub mod jolo;
#[cfg(feature = "keriox")]
pub mod keri;
#[cfg(feature = "didkey")]
pub mod key;

#[cfg(feature = "keriox")]
use crate::keri::DidKeriResolver;
#[cfg(feature = "didkey")]
use key::DidKeyResolver;

use base58::FromBase58;
pub use did_key::{Document, KeyFormat, VerificationMethod};
use error::Error;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};

lazy_static! {
    static ref DID_REGEX: Regex = Regex::new(
        r"(?x)(?P<prefix>[did]{3}):(?P<method>[a-z]*):(?P<key_id>[-_a-zA-Z0-9]*)([:?/]?)(S)*??",
    )
    .unwrap();
}

/// # Universal trait for DID document resolver.
/// Standardises signature for resolver output.
///
pub trait DdoResolver {
    /// Method signature for DID Document resolver.
    ///
    /// # Parameters
    /// `did_url` - proper DID url starts with "did:" followed up by
    ///     method name, path, etc. Details in spec:
    ///     https://www.w3.org/TR/did-core/#did-url-syntax
    ///
    fn resolve(&self, did_url: &str) -> Result<Document, Error>;
}

/// # Universal trait for DID document parser methods.
/// Provides method signatures to search through the document
///     for particular elements or public crypto material.
///
pub trait DdoParser {
    /// Pattern finding method to resolve `KeyAgreement` based on provided
    /// `pattern`. Returns `None` if no matching result found instead of error.
    ///
    fn find_key_agreement(&self, pattern: &str) -> Option<KeyAgreement>;
    /// Searches all crypto matherial in the document for particular curve and
    ///     returns FIRST! match for particular `curve`, which can be partial pattern.
    /// Returns `None` if no matching result found instead of error.
    ///
    fn find_public_key_for_curve(&self, curve: &str) -> Option<Vec<u8>>;
    /// Method similar to `find_key_agreement`, but returns key `ID` instead of the
    ///     key itself.
    /// Returns `None` if no matching result found instead of error.
    ///
    fn find_public_key_id_for_curve(&self, curve: &str) -> Option<String>;
    /// Resolve controller for specified curve if it's present in `VerificationMethod`s list
    /// Returns `None` if no matching curve found.
    ///
    fn find_public_key_controller_for_curve(&self, curve: &str) -> Option<String>;
}

impl DdoParser for Document {
    fn find_key_agreement(&self, pattern: &str) -> Option<KeyAgreement> {
        let agreements = self.key_agreement.clone();
        if agreements.is_none() {
            return None;
        }
        match agreements.unwrap().iter().find(|a| a.contains(pattern)) {
            Some(a) => serde_json::from_str(a).unwrap_or(None),
            None => None,
        }
    }
    fn find_public_key_for_curve(&self, curve: &str) -> Option<Vec<u8>> {
        if let Some(k) = self
            .verification_method
            .iter()
            .find(|m| m.key_type.contains(curve))
        {
            if let Some(key) = k.public_key.clone() {
                match key {
                    KeyFormat::Base58(value) => Some(value.from_base58().unwrap()),
                    KeyFormat::Multibase(value) => Some(value),
                    KeyFormat::JWK(_value) => todo!(), // FIXME: proper return should be implemented
                }
            } else {
                None
            }
        } else {
            None
        }
    }
    fn find_public_key_id_for_curve(&self, curve: &str) -> Option<String> {
        match get_public_key(self, curve) {
            Some(kf) => match kf {
                KeyFormat::JWK(key) => key.key_id,
                _ => None,
            },
            None => None,
        }
    }
    fn find_public_key_controller_for_curve(&self, curve: &str) -> Option<String> {
        match self
            .verification_method
            .iter()
            .find(|vm| vm.key_type.contains(curve))
        {
            Some(vm) => Some(vm.controller.to_owned()),
            None => None,
        }
    }
}

/// Helper function to try resolve any document based on provided `did_url` instead
///     of calling `DdoResolver::resolve()` directly.
/// This function provides convenience but is dependant on resolver features enabled
///     and will have overhead comparing to direct trait call of specific resolver,
///     therefore should be used with consideration.
/// Output is `Document` or `Error`.
///
pub fn try_resolve_any(did_url: &str) -> Result<Document, Error> {
    let re = regex::Regex::new(r"^((?P<prefix>did){1}:(?P<method>[-_A-Za-z0-9]*){1}:(?P<id>.+?))((?P<kerlid>\?kerl=)(?P<kerl>[a-zA-Z0-9]+?))?$").unwrap();
    match re.captures(did_url) {
        Some(caps) => {
            match &caps["method"] {
                #[cfg(feature = "didkey")]
                "key" => DidKeyResolver {}
                    .resolve(did_url)
                    .map_err(|e| error::Error::DidKeyError(e.to_string())),
                #[cfg(feature = "keriox")]
                "keri" => match &caps["kerlid"] {
                    "" => Err(error::Error::DidKeriError("kerl id not found".into())),
                    _ => match &caps["kerl"] {
                        "" => Err(error::Error::DidKeriError("kerl not found".into())),
                        _ => DidKeriResolver::new(&String::from_utf8_lossy(&base64_url::decode(
                            &caps["kerl"],
                        )?))
                        .resolve(&format!("did:keri:{}", &caps["id"])),
                    },
                },
                _ => Err(error::Error::DidKeyError("not supported key url".into())), // TODO: separate descriptive error
            }
        }
        None => Err(error::Error::DidKeyError("not a did url".into())), // TODO: separate descriptive error
    }
}

/// Helper function to try resolve any document based on provided `did_url` instead
///     of calling `DdoResolver::resolve()` directly.
/// This function provides convenience but is dependant on resolver features enabled
///     and will have overhead comparing to direct trait call of specific resolver,
///     therefore should be used with consideration.
/// Output is Option: `Some(Document)` or `None`. Will never fail with error.
///
pub fn resolve_any(did_url: &str) -> Option<Document> {
    let re = regex::Regex::new(r"^((?P<prefix>did){1}:(?P<method>[-_a-zA-Z0-9]*){1}:(?P<id>.+?))((?P<kerlid>\?kerl=)(?P<kerl>[a-zA-Z0-9]+?))?$").unwrap();
    match re.captures(did_url) {
        Some(caps) => {
            let resolver: Box<dyn DdoResolver> = match &caps["method"] {
                #[cfg(feature = "didkey")]
                "key" => Box::new(DidKeyResolver {}),
                #[cfg(feature = "keriox")]
                "keri" => Box::new(DidKeriResolver::new(&String::from_utf8_lossy(
                    &base64_url::decode(&caps["kerl"]).unwrap_or(vec![]),
                ))),
                #[cfg(feature = "didjolo")]
                "jolo" => {}
                #[cfg(feature = "didweb")]
                "web" => {}
                _ => return None,
            };
            let parsed_url = format!("{}:{}:{}", &caps["prefix"], &caps["method"], &caps["id"]);
            match resolver.resolve(&parsed_url) {
                Ok(doc) => Some(doc),
                Err(_) => None,
            }
        }
        None => None,
    }
}

// FIXME: complete this implementation
pub fn get_sign_and_crypto_keys<'a>(ddo: &'a Document) -> (Option<&'a [u8]>, Option<&'a [u8]>) {
    let _sign_key = ddo.verification_method.iter().fold(None, |_, vm| {
        vm.public_key.iter().find(|k| match k {
            KeyFormat::JWK(key) => key.curve == "Ed25519",
            _ => false,
        })
    });
    let _crypto_key = ddo
        .verification_method
        .iter()
        .find(|vm| vm.key_type == "X25519");
    (None, None)
}

// Helper function to get full `KeyFormat` from the document by it's curve type
pub(crate) fn get_public_key(doc: &Document, curve: &str) -> Option<KeyFormat> {
    match doc
        .verification_method
        .iter()
        .find(|m| match &m.public_key {
            Some(KeyFormat::JWK(jwk)) => jwk.curve.contains(curve),
            _ => false,
        }) {
        Some(vm) => vm.public_key.clone(),
        None => None,
    }
}

// Helper function to get key id from did url
// # + id
pub(crate) fn key_id_from_didurl(url: &str) -> String {
    match DID_REGEX.captures(url) {
        Some(s) => match s.name("key_id") {
            Some(name) => format!("#{}", name.as_str()),
            None => String::default(),
        },
        None => String::default(),
    }
}

// Parses and String formats prefix:method:key_id from given &str
//
pub fn did_id_from_url(url: &str) -> Option<String> {
    let captures = DID_REGEX.captures(url)?;
    Some(format!(
        "{}:{}:{}",
        captures.name("prefix")?.as_str(),
        captures.name("method")?.as_str(),
        captures.name("key_id")?.as_str()
    ))
}

/// "Temporary" struct to extend did_key crate's `Document` with `KeyAgreement` instead of string.
///
#[cfg(feature = "didkey")]
#[derive(Serialize, Deserialize, Debug)]
pub struct KeyAgreement {
    pub id: String,
    pub r#type: String,
    pub controller: String,
    #[serde(rename = "publicKeyBase58")]
    pub public_key_base58: String,
}

#[test]
fn did_id_from_url_test() {
    let keri = "did:keri:someiderNTIFIER2345432?bunch_of_niose!_$(#)";
    let keri_sym = "did:keri:D1bkcOzM-YwEXKPc5yHbMzkHRrZS3O6QAVEpGsS0XpF_E";
    let key = "did:key:bu03rlnth4gpk09y4cr3DEGCTHUDGc45RCGUCH?again_some_rubbish";
    let long = "did:verylongid:BXDHCG8765678THDIYFGCRNWMBXIF34543HDGC?MOREnoise_?";
    let not_a_did = "thisisnot_a_did";
    assert_eq!(
        &did_id_from_url(keri).unwrap(),
        "did:keri:someiderNTIFIER2345432"
    );
    assert_eq!(
        &did_id_from_url(keri_sym).unwrap(),
        "did:keri:D1bkcOzM-YwEXKPc5yHbMzkHRrZS3O6QAVEpGsS0XpF_E"
    );
    assert_eq!(
        &did_id_from_url(key).unwrap(),
        "did:key:bu03rlnth4gpk09y4cr3DEGCTHUDGc45RCGUCH"
    );
    assert_eq!(
        &did_id_from_url(long).unwrap(),
        "did:verylongid:BXDHCG8765678THDIYFGCRNWMBXIF34543HDGC"
    );
    assert!(did_id_from_url(not_a_did).is_none());
}
