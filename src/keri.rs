use keri::{
    derivation::basic::Basic, event_parsing::message::signed_event_stream, prefix::Prefix,
    state::IdentifierState,
};

use crate::{key_id_from_didurl, DdoResolver, Document, Error, KeyFormat, VerificationMethod};

pub struct DidKeriResolver {
    state: IdentifierState,
}

impl DidKeriResolver {
    pub fn new(state: &str) -> Self {
        DidKeriResolver {
            state: mem_parse(state),
        }
    }
}

impl DdoResolver for DidKeriResolver {
    fn resolve(&self, did_url: &str) -> Result<Document, Error> {
        Ok(Document {
            context: "https://www.w3.org/ns/did/v1".into(),
            id: did_url.into(),
            verification_method: self
                .state
                .current
                .public_keys
                .iter()
                .map(|prefix| VerificationMethod {
                    id: key_id_from_didurl(did_url),
                    key_type: as_string(&prefix.derivation),
                    controller: did_url.into(),
                    public_key: Some(KeyFormat::Multibase(prefix.derivative().to_vec())),
                    private_key: None,
                })
                .collect::<Vec<VerificationMethod>>(),
            assertion_method: None,
            authentication: None,
            capability_delegation: None,
            capability_invocation: None,
            // FIXME: populate this with references of X* key refs
            // https://www.w3.org/TR/did-core/#dfn-keyagreement
            key_agreement: None,
        })
    }
}

// Helper method to get string representation of keri key type
fn as_string(b: &Basic) -> String {
    match b {
        Basic::Ed25519NT | Basic::Ed25519 => "Ed25519VerificationKey2018".into(),
        Basic::ECDSAsecp256k1 | Basic::ECDSAsecp256k1NT => {
            "EcdsaSecp256k1VerificationKey2019".into()
        }
        Basic::X25519 => "X25519KeyAgreementKey2019".into(),
        _ => "bad key type".into(),
    }
}

// In memory kel parser method
// TODO: PROPER ERROR HANDLING!
fn mem_parse(kel: impl AsRef<[u8]>) -> IdentifierState {
    signed_event_stream(kel.as_ref())
        .unwrap()
        .1
        .into_iter()
        .fold(vec![], |mut accum, e| {
            accum.push(e.deserialized_event);
            accum
        })
        .iter()
        .fold(IdentifierState::default(), |accum, e| {
            accum.apply(e).unwrap()
        })
}

#[cfg(test)]
mod did_keri_tests {
    use super::*;
    use crate::{resolve_any, try_resolve_any, DdoParser};
    use base64_url::encode;

    #[test]
    fn public_key_by_type_search_ed25519_test() {
        let kerl_str = br#"{"v":"KERI10JSON00014b_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAAhcaP-l0DkIKlJ87iIVcDx-m0iKPdSArEu63b-2cSEn9wXVGNpWw9nfwxodQ9G8J3q_Pm-AWfDwZGD9fobWuHBAAB6mz7zP0xFNBEBfSKG4mjpPbeOXktaIyX8mfsEa1A3Psf7eKxSrJ5Woj3iUB2AhhLg412-zkk795qxsK2xfdxBAACj5wdW-EyUJNgW0LHePQcSFNxW3ZyPregL4H2FoOrsPxLa3MZx6xYTh6i7YRMGY50ezEjV81hkI1Yce75M_bPCQ"#;
        let dkr = DidKeriResolver::new(&String::from_utf8_lossy(kerl_str));
        let d = dkr.resolve("did:keri:EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8");
        assert!(d.is_ok());
        let d = d.unwrap();
        let k = d.find_public_key_for_curve("Ed25519");
        assert!(k.is_some());
    }

    #[test]
    fn public_key_by_type_search_x25519_test() {
        let kerl_str = r#"{"v":"KERI10JSON00011c_","i":"ENRHENIVTtS1VmS1_a04BDgdsmCf1aff1-tZvfT_f4sU","s":"0","t":"icp","kt":"1","k":["DMXkLnbZZ2g_oWGzaVz7LLmqtLpI72Y4GYsBsgJfBjF4","Cz-LsoY7B6foopEV_4Cpj0ubK3VIlJ_dELmjlwmirDuU"],"n":"EiZOdQzNE8-jGNfeAFAhb7T39eyxFy0lNXE-wYzAAVLA","bt":"0","b":[],"c":[],"a":[]}-AABAA9-soOfrjhPJE4bzlzhqSYKOIAAfTPzDM7ZNskZQ323IktarZYpc1NU178tAIYFErpDt6hoDbeE9dBsDXd3BJCw";
        let dkr = DidKeriResolver::new(kerl_str);
        let d = dkr.resolve("did:keri:EOC0EjXm9YYNVEt6meJpYhbX3bvRPdVyGWmd1JWu-6KY");
        assert!(d.is_ok());
        let d = d.unwrap();
        let k = d.find_public_key_for_curve("X25519");
        assert!(k.is_some());
    }

    #[test]
    fn resolve_any_keri_test() {
        let kerl_str = r#"{"v":"KERI10JSON00014b_","i":"EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8","s":"0","t":"icp","kt":"2","k":["DSuhyBcPZEZLK-fcw5tzHn2N46wRCG_ZOoeKtWTOunRA","DVcuJOOJF1IE8svqEtrSuyQjGTd2HhfAkt9y2QkUtFJI","DT1iAhBWCkvChxNWsby2J0pJyxBIxbAtbLA0Ljx-Grh8"],"n":"E9izzBkXX76sqt0N-tfLzJeRqj0W56p4pDQ_ZqNCDpyw","bt":"0","b":[],"c":[],"a":[]}-AADAAhcaP-l0DkIKlJ87iIVcDx-m0iKPdSArEu63b-2cSEn9wXVGNpWw9nfwxodQ9G8J3q_Pm-AWfDwZGD9fobWuHBAAB6mz7zP0xFNBEBfSKG4mjpPbeOXktaIyX8mfsEa1A3Psf7eKxSrJ5Woj3iUB2AhhLg412-zkk795qxsK2xfdxBAACj5wdW-EyUJNgW0LHePQcSFNxW3ZyPregL4H2FoOrsPxLa3MZx6xYTh6i7YRMGY50ezEjV81hkI1Yce75M_bPCQ"#;
        let full_kerl_with_url = format!(
            "did:keri:EsiHneigxgDopAidk_dmHuiUJR3kAaeqpgOAj9ZZd4q8?kerl={}",
            encode(kerl_str)
        );
        let res = resolve_any(&full_kerl_with_url);
        assert!(res.is_some());
        let doc = res.unwrap();
        let key = doc.find_public_key_for_curve("Ed25519");
        assert!(key.is_some());
    }

    #[test]
    fn try_resolve_any_keri_test() {
        let kerl_str = r#"{"v":"KERI10JSON0000ed_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"0","t":"icp","kt":"1","k":["DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk"],"n":"EGofBtQtAeDMOO3AA4QM0OHxKyGQQ1l2HzBOtrKDnD-o","bt":"0","b":[],"c":[],"a":[]}-AABAAxemWo-mppcRkiGSOXpVwh8CYeTSEJ-a0HDrCkE-TKJ-_76GX-iD7s4sbZ7j5fdfvOuTNyuFw3a797gwpnJ-NAg{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"1","t":"rot","p":"EvZY9w3fS1h98tJeysdNQqT70XLLec4oso8kIYjfu2Ks","kt":"1","k":["DLqde_jCw-C3y0fTvXMXX5W7QB0188bMvXVkRcedgTwY"],"n":"EW5MfLjWGOUCIV1tQLKNBu_WFifVK7ksthNDoHP89oOc","bt":"0","br":[],"ba":[],"a":[]}-AABAAuQcoYU04XYzJxOPp4cxmvXbqVpGADfQWqPOzo1S6MajUl1sEWEL1Ry30jNXaV3-izvHRNROYtPm2LIuIimIFDg{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"2","t":"rot","p":"EOi_KYKjP4hinuTfgtoYj5QBw_Q1ZrRtWFQDp0qsNuks","kt":"1","k":["De5pKs8wiP9bplyjspW9L62PEANoad-5Kum1uAllRxPY"],"n":"ERKagV0hID1gqZceLsOV3s7MjcoRmCaps2bPBHvVQPEQ","bt":"0","br":[],"ba":[],"a":[]}-AABAAPKIYNAm6nmz4cv37nvn5XMKRVzfKkVpJwMDt2DG-DqTJRCP8ehCeyDFJTdtvdJHjKqrnxE4Lfpll3iUzuQM4Aw{"v":"KERI10JSON000122_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"3","t":"rot","p":"EVK1FbLl7yWTxOzPwk7vo_pQG5AumFoeSE51KapaEymc","kt":"1","k":["D2M5V_e23Pa0IAqqhNDKzZX0kRIMkJyW8_M-gT_Kw9sc"],"n":"EYJkIfnCYcMFVIEi-hMMIjBQfXcTqH_lGIIqMw4LaeOE","bt":"0","br":[],"ba":[],"a":[]}-AABAAsrKFTSuA6tEzqV0C7fEbeiERLdZpStZMCTvgDvzNMfa_Tn26ejFRZ_rDmovoo8xh0dH7SdMQ5B_FvwCx9E98Aw{"v":"KERI10JSON000098_","i":"DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk","s":"4","t":"ixn","p":"EY7VDg-9Gixr9rgH2VyWGvnnoebgTyT9oieHZIaiv2UA","a":[]}-AABAAqHtncya5PNnwSbMRegftJc1y8E4tMZwajVVj2-FmGmp82b2A7pY1vr7cv36m7wPRV5Dusf4BRa5moMlHUpSqDA"#;
        let full_kerl_with_url = format!(
            "did:keri:DoQy7bwiYr80qXoISsMdGvfXmCCpZ9PUqetbR8e-fyTk?kerl={}",
            encode(kerl_str)
        );
        let res = try_resolve_any(&full_kerl_with_url);
        assert!(res.is_ok());
        let doc = res.unwrap();
        let key = doc.find_public_key_for_curve("Ed25519");
        assert!(key.is_some());
    }
}
