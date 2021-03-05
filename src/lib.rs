pub mod error;

use base58::FromBase58;
pub use did_key::*;
use error::Error;
use serde::{Serialize, Deserialize};

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
    fn resolve(did_url: &str) -> Result<Document, Error>;
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
}

/// Unit struct which have implementations of `DdoParser` and `DdoResolver`
///     traits for `did:key` document resolver.
///
#[cfg(feature = "didkey")]
pub struct DidKeyResolver{}

#[cfg(feature = "didkey")]
impl DdoResolver for DidKeyResolver {
    fn resolve(did_url: &str) -> Result<Document, Error> {
        let key = did_key::resolve(did_url)
            .map_err(|e| error::Error::DidKeyError(format!("{:?}", e)))?;
        Ok(key.get_did_document(did_key::CONFIG_LD_PUBLIC))
    }
}

#[cfg(feature = "didkey")]
impl DdoParser for Document {
    fn find_key_agreement(&self, pattern: &str) -> Option<KeyAgreement> {
        let agreements = self.key_agreement.clone();
        if agreements.is_none() { return None; }
        match agreements.unwrap()
            .iter().find(|a| a.contains(pattern)) {
                Some(a) => serde_json::from_str(a).unwrap_or(None),
                None => None
            }
    }
    fn find_public_key_for_curve(&self, curve: &str) -> Option<Vec<u8>> {
        if let Some(k) = self.verification_method.iter().find(|m| {
            m.key_type.contains(curve)
        }) {
            if let Some(key) = k.public_key.clone() {
                match key {
                    KeyFormat::Base58(value) => Some(value.from_base58().unwrap()),
                    KeyFormat::Multibase(value) => Some(value),
                    KeyFormat::JWK(_value) => todo!() // FIXME: proper return should be implemented
                }
            } else { None }
        } else {
            None
        }
    }
    fn find_public_key_id_for_curve(&self, curve: &str) -> Option<String> {
        match get_public_key(self, curve) {
            Some(kf) => match kf {
                KeyFormat::JWK(key) => key.key_id,
                _ => None
            },
            None => None
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
    let re = regex::Regex::new(r"(?x)(?P<prefix>[did]{3}):(?P<method>[a-z]*):").unwrap();
    match re.captures(did_url) {
        Some(caps) => {
            match &caps["method"] {
                "key" => DidKeyResolver::resolve(did_url)
                    .map_err(|e| error::Error::DidKeyError(e.to_string())),
                _ => Err(error::Error::DidKeyError("not supported key url".into())) // TODO: separate descriptive error
            }
        },
        None => Err(error::Error::DidKeyError("not a did url".into())) // TODO: separate descriptive error
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
    let re = regex::Regex::new(r"(?x)(?P<prefix>[did]{3}):(?P<method>[a-z]*):").unwrap();
    match re.captures(did_url) {
        Some(caps) => {
            match &caps["method"] {
                #[cfg(feature = "didkey")]
                "key" => { if let Ok(doc) = DidKeyResolver::resolve(did_url) {
                        Some(doc)
                    } else { None }
                },
                #[cfg(feature = "didjolo")]
                "jolo" => {},
                #[cfg(feature = "didweb")]
                "web" => {},
                _ => None
            }
        },
        None => None,
    }
}

// FIXME: complete this implementation
pub fn get_sign_and_crypto_keys<'a>(ddo: &'a Document) -> (Option<&'a [u8]>, Option<&'a [u8]>) {
    let sign_key= ddo.verification_method.iter().fold(
        None,
        |_, vm| vm.public_key.iter().find(
            |k| match k {
                KeyFormat::JWK(key) => key.curve == "Ed25519",
                _ => false
            }));
    let crypto_key = ddo.verification_method.iter().find(|vm| vm.key_type == "X25519");
    (None, None)
}

// Helper function to get full `KeyFormat` from the document by it's curve type
fn get_public_key(doc: &Document, curve: &str) -> Option<KeyFormat> {
    match doc.verification_method.iter().find(|m| {
        match &m.public_key {
            Some(KeyFormat::JWK(jwk)) => jwk.curve.contains(curve),
            _ => false
        }
    }) {
        Some(vm) => vm.public_key.clone(),
        None => None
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_resolve_raw_test() {
        let k = did_key::resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
        assert!(k.is_ok());
        let doc = k.unwrap().get_did_document(did_key::CONFIG_LD_PUBLIC);
        println!("{:?}", doc);
    }

    #[test]
    fn did_key_resolve_trait_test() {
        let r = DidKeyResolver::resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
        assert!(r.is_ok());
    }

    #[test]
    fn resolve_any_test() {
        let d = resolve_any("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
        assert!(d.is_some());
    }

    #[test]
    fn public_key_by_type_search_test() {
        let d = resolve_any("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
        assert!(d.is_some());
        let k = d.unwrap().find_public_key_for_curve("X25519");
        assert!(k.is_some());
    }
}
