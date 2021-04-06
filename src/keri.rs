use keri::{
    derivation::basic::Basic,
    prefix::Prefix,
    state::IdentifierState,
};

use crate::{
    DdoResolver,
    Document,
    KeyFormat,
    VerificationMethod,
    Error,
    key_id_from_didurl,
};

pub struct DidKeriResolver {
    state: IdentifierState
}

impl DidKeriResolver {
    pub fn new(state: &str) -> Self {
        DidKeriResolver {
            state: state.into()
        }
    }
}

impl DdoResolver for DidKeriResolver {
   fn resolve(&self, did_url: &str) -> Result<Document, Error> {
        Ok(Document {
            context: "https://www.w3.org/ns/did/v1".into(),
            id: did_url.into(),
            verification_method: self.state
                .current
                .public_keys
                .iter()
                .map(|prefix| VerificationMethod {
                    id: key_id_from_didurl(did_url),
                    key_type: as_string(&prefix.derivation),
                    controller: did_url.into(),
                    public_key: Some(KeyFormat::Multibase(prefix.derivative().to_vec())),
                    private_key: None
                })
                .collect::<Vec<VerificationMethod>>(),
            assertion_method: None,
            authentication: None,
            capability_delegation: None,
            capability_invocation: None,
            key_agreement: None
        })
   }
}

// Helper method to get string representation of keri key type
fn as_string(b: &Basic) -> String {
    match b {
        Basic::Ed25519NT | Basic::Ed25519 => "Ed25519VerificationKey2018".into(),
        Basic::ECDSAsecp256k1 | Basic::ECDSAsecp256k1NT => "EcdsaSecp256k1VerificationKey2019".into(),
        Basic::X25519 => "X25519KeyAgreementKey2019".into(),
        _ => "bad key type".into()
    }
}

#[cfg(test)]
mod did_keri_tests {
    use super::*;
    use crate::DdoParser;

    #[test]
    fn public_key_by_type_search_test() {
        let dkr = DidKeriResolver::new("");
        let d = dkr.resolve("did:keri:somethinggoeshere");
        assert!(d.is_ok());
        let k = d.unwrap().find_public_key_for_curve("X25519");
        assert!(k.is_some());
    }
}

