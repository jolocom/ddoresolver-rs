use keri::{
    derivation::basic::Basic,
    prefix::Prefix,
    state::IdentifierState,
    event_message::parse::{
        Deserialized,
        signed_event_stream,
    },
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
            state: mem_parse(state)
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

// In memory kel parser method
// TODO: PROPER ERROR HANDLING!
fn mem_parse(kel: impl AsRef<[u8]>) -> IdentifierState {
    signed_event_stream(kel.as_ref())
        .unwrap().1
        .into_iter().fold(vec!(), |mut accum, e| {
            if let Deserialized::Event(ev) = e {
                accum.push(ev.event);
                accum 
            } 
            else { accum }
        })
        .iter()
        .fold(IdentifierState::default(), |accum, e| accum.apply(&e.event).unwrap())
}

#[cfg(test)]
mod did_keri_tests {
    use super::*;
    use crate::{
        DdoParser,
        resolve_any,
        try_resolve_any,
    };
    use base64_url::encode;

    #[test]
    fn public_key_by_type_search_ed25519_test() {
        let kerl_str = br#"{"v":"KERI10JSON0000e6_","i":"Dw6a91H7DSGKViP5rXvq3ToosLbsD9EQvwEAP2h4fp5w","s":"0","t":"icp","kt":"1","k":["Dw6a91H7DSGKViP5rXvq3ToosLbsD9EQvwEAP2h4fp5w"],"n":"EASFIEHtrEl7m-4L4_6fLUwE8VSsWVyw_2si5vb4jnrk","wt":"0","w":[],"c":[]}-AABAAttCGUqzUu8rQPl9TkPzs-MuczytlwI6XUekUeoa6waaY9hHWPpetFJ5M0zjEdFUR1s0kN0U5n-jyk-r-K0vUDg{"v":"KERI10JSON000122_","i":"Dw6a91H7DSGKViP5rXvq3ToosLbsD9EQvwEAP2h4fp5w","s":"1","t":"rot","p":"EuCdQ84sUCImYeXgfDcoIPYW1pQ6WBBIQHAfyGRKGN4Q","kt":"1","k":["DoCl1sPSeuzGoLQ_83qHtuZeAVThLu13kb4k23FkVDOg"],"n":"EiFDXLjMHWktBaDptBlmWvarRGO2G--7eUUllWwYJDyE","wt":"0","wr":[],"wa":[],"a":[]}-AABAAMg3D1oTUIuaDymERF-zD6tF1r9EatcOTcRQ1EQEV1h9CQoBSqfasfQBymyJDo2IOPA5hqirLqMfajZSoTgKZAg{"v":"KERI10JSON000122_","i":"Dw6a91H7DSGKViP5rXvq3ToosLbsD9EQvwEAP2h4fp5w","s":"2","t":"rot","p":"EA31ALscbTvnpsA0Uhl9euQYm9bVmHtNvP8I3Ctz8RGM","kt":"1","k":["DGTEck3tn-RmmvVpQb9YJyXSkTVrW8umwUzXQbsDDo3s"],"n":"E3bqoGXtOr6blxbatLZkv9g-Eap0247DOJh4jD81H4g4","wt":"0","wr":[],"wa":[],"a":[]}-AABAAoQCoJb3adFGNXHE9TF-e_efDGu1BJPQyCHZr6kHc1tYp0olKfdKAcYIN_JSGgtLMYKwswLq__KYIRtMfg-U4Bg{"v":"KERI10JSON0000cc_","i":"Dw6a91H7DSGKViP5rXvq3ToosLbsD9EQvwEAP2h4fp5w","s":"3","t":"ixn","p":"EIdLcIxlYfZuk20iUXuWLDVi8wXuGU38yvBIu-Ac_2w8","a":[{"d":"Ey9J7Ef2rjpSot3EahpwllhDzUWRynt7Z_J5TG_5OZS8"}]}-AABAA3yC6xkpug37v9Wkh5ctejpjYzPArAbnk70_HQ4CaeCzFbuu8KJhqkkH2voSLBqntU9AGrKMALjrsyXN9JVBCDQ{"v":"KERI10JSON000122_","i":"Dw6a91H7DSGKViP5rXvq3ToosLbsD9EQvwEAP2h4fp5w","s":"4","t":"rot","p":"EF5TFIpq4u_8DCu8CRqcJ_naeQ0Gj5URqjLkRYozTvbE","kt":"1","k":["DLngmY2lz5xtBJ3K8vzwDVnp2_57GOXS7Eph9ainHBm4"],"n":"Egq_ChqsiVDfFBMJSdqsJEGBu35pjYrsr59IHLLfw5Es","wt":"0","wr":[],"wa":[],"a":[]}-AABAAL6jWv7NkOEiqV59Z7DWva0RwL64xwgV8TeNRl-ucYj6bQyVWamL42742C3_s8ZYBte5zQq15pvFU8E3JfDO0CQ"#;
        let dkr = DidKeriResolver::new(&String::from_utf8_lossy(kerl_str));
        let d = dkr.resolve("did:keri:Dw6a91H7DSGKViP5rXvq3ToosLbsD9EQvwEAP2h4fp5w");
        assert!(d.is_ok());
        let k = d.unwrap().find_public_key_for_curve("Ed25519");
        assert!(k.is_some());
    }

    #[test]
    fn public_key_by_type_search_x25519_test() {
        let kerl_str = r#"{"v":"KERI10JSON000115_","i":"E6hwQjTM81XBKO05JxpjO11e3SY-jJfs2vatUr3nVdy4","s":"0","t":"icp","kt":"1","k":["DG9Q4wQ87Q5VKv6HJ6b22hY2famnwBibEMQr7-d7sn5c","CIOa96x9rTFbbMkcgbd3yMErXTJMqPMWhH11gZq1vNHc"],"n":"EHZM6aLLfh_dW0YgInXCBHESUNNlZkzgfurKPzyKHnIE","wt":"0","w":[],"c":[]}-AABAARkUt2sJQ743MUhWLH4ggqbklE-2gbE4gd07vjfgWmR6FT-5hcVODhmydbyBfzzLyuMM6CicAN9ZIFNFEyfAbBQ"#;
        let dkr = DidKeriResolver::new(kerl_str);
        let d = dkr.resolve("did:keri:E6hwQjTM81XBKO05JxpjO11e3SY-jJfs2vatUr3nVdy4");
        assert!(d.is_ok());
        let k = d.unwrap().find_public_key_for_curve("X25519");
        assert!(k.is_some());
    }

    #[test]
    fn resolved_public_key_found_crypto_match_test() {
        let kerl_str = r#"{"v":"KERI10JSON000115_","i":"Eh9Gq4--Q1OVxJEL7M49-a5k7iEJATqSAxQiRLwJEja4","s":"0","t":"icp","kt":"1","k":["D7sD1K7bTfG4E8ObJa4Ecd6zuML1diINCvKXy_o1FK60","CFyJrFXQYvDYiK0c7CLIisfq6xO-D0gqjW0ThtVKObHs"],"n":"E1IzcG1u6Iy5onwrCG1AKcj9KUJ-0rbMq_t6yViIgv2U","wt":"0","w":[],"c":[]}-AABAAlccRMa44Jo07A_fuOwDP6Fu9_3PArGIKYCo7F9U8OC_02d5p26LuenliVDkmp7DV9hyYUHeWIug6PsIZlUlKAg"#;
        let dkr = DidKeriResolver::new(kerl_str);
        let d = dkr.resolve("did:keri:Eh9Gq4--Q1OVxJEL7M49-a5k7iEJATqSAxQiRLwJEja4");
        assert!(d.is_ok());
        let k = d.unwrap().find_public_key_for_curve("X25519");
        assert!(k.is_some());
        let private_key = [32, 199, 55, 194, 109, 85, 48, 152, 86, 44, 207, 86, 238, 104, 152, 236, 164, 204, 88, 155, 212, 111, 146, 34, 111, 241, 4, 224, 165, 71, 180, 116]; 
        let expected_public_key = [23, 34, 107, 21, 116, 24, 188, 54, 34, 43, 71, 59, 8, 178, 34, 177, 250, 186, 196, 239, 131, 210, 10, 163, 91, 68, 225, 181, 82, 142, 108, 123];
        let k = k.unwrap();
        assert_eq!(k, expected_public_key);

        use x25519_dalek::{PublicKey, StaticSecret};
        let ss = StaticSecret::from(private_key);
        let pk = PublicKey::from(&ss);
        assert_eq!(&pk.to_bytes().to_vec(), &k);
    }

    #[test]
    fn resolve_any_keri_test() {
        let kerl_str = r#"{"v":"KERI10JSON000115_","i":"E6hwQjTM81XBKO05JxpjO11e3SY-jJfs2vatUr3nVdy4","s":"0","t":"icp","kt":"1","k":["DG9Q4wQ87Q5VKv6HJ6b22hY2famnwBibEMQr7-d7sn5c","CIOa96x9rTFbbMkcgbd3yMErXTJMqPMWhH11gZq1vNHc"],"n":"EHZM6aLLfh_dW0YgInXCBHESUNNlZkzgfurKPzyKHnIE","wt":"0","w":[],"c":[]}-AABAARkUt2sJQ743MUhWLH4ggqbklE-2gbE4gd07vjfgWmR6FT-5hcVODhmydbyBfzzLyuMM6CicAN9ZIFNFEyfAbBQ"#;
        let full_kerl_with_url = format!("did:keri:E6hwQjTM81XBKO05JxpjO11e3SY-jJfs2vatUr3nVdy4?kerl={}", encode(kerl_str));
        let res = resolve_any(&full_kerl_with_url);
        assert!(res.is_some());
        let doc = res.unwrap();
        let key = doc.find_public_key_for_curve("X25519");
        assert!(key.is_some());
    }

    #[test]
    fn try_resolve_any_keri_test() {
        let kerl_str = r#"{"v":"KERI10JSON000115_","i":"Eh9Gq4--Q1OVxJEL7M49-a5k7iEJATqSAxQiRLwJEja4","s":"0","t":"icp","kt":"1","k":["D7sD1K7bTfG4E8ObJa4Ecd6zuML1diINCvKXy_o1FK60","CFyJrFXQYvDYiK0c7CLIisfq6xO-D0gqjW0ThtVKObHs"],"n":"E1IzcG1u6Iy5onwrCG1AKcj9KUJ-0rbMq_t6yViIgv2U","wt":"0","w":[],"c":[]}-AABAAlccRMa44Jo07A_fuOwDP6Fu9_3PArGIKYCo7F9U8OC_02d5p26LuenliVDkmp7DV9hyYUHeWIug6PsIZlUlKAg"#;
        let full_kerl_with_url = format!("did:keri:Eh9Gq4--Q1OVxJEL7M49-a5k7iEJATqSAxQiRLwJEja4?kerl={}", encode(kerl_str));
        let res = try_resolve_any(&full_kerl_with_url);
        assert!(res.is_ok());
        let doc = res.unwrap();
        let key = doc.find_public_key_for_curve("X25519");
        assert!(key.is_some());
    }
}

