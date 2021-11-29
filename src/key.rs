use crate::{DdoResolver, Error};
pub use did_key::*;

/// Unit struct which have implementations of `DdoParser` and `DdoResolver`
///     traits for `did:key` document resolver.
///
pub struct DidKeyResolver {}

impl DdoResolver for DidKeyResolver {
    fn resolve(&self, did_url: &str) -> Result<Document, Error> {
        let key = did_key::resolve(did_url).map_err(|e| Error::DidKeyError(format!("{:?}", e)))?;
        Ok(key.get_did_document(did_key::CONFIG_LD_PUBLIC))
    }
}

#[cfg(test)]
mod did_key_tests {
    use super::*;
    use crate::{resolve_any, DdoParser};

    #[test]
    fn did_key_resolve_raw_test() {
        let k = did_key::resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
        assert!(k.is_ok());
        let _doc = k.unwrap().get_did_document(did_key::CONFIG_LD_PUBLIC);
    }

    #[test]
    fn did_key_resolve_trait_test() {
        let r =
            DidKeyResolver {}.resolve("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp");
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
