pub mod error;

use did_key::*;

pub trait DdoResolve {
    fn resolve(did_url: &str) -> Result<Document, error::Error>;
}

pub struct DidKeyResolver{}

impl DdoResolve for DidKeyResolver {
    fn resolve(did_url: &str) -> Result<Document, error::Error> {
        let key = did_key::resolve(did_url)
            .map_err(|e| error::Error::DidKeyError(format!("{:?}", e)))?;
        Ok(key.get_did_document(did_key::CONFIG_LD_PUBLIC))
    }
}

pub fn resolve_any(did_url: &str) -> Option<Document> {
    let re = regex::Regex::new(r"(?x)(?P<prefix>[did]{3}):(?P<method>[a-z]*):").unwrap();
    match re.captures(did_url) {
        Some(caps) => {
            match &caps["method"] {
                "key" => { if let Ok(doc) = DidKeyResolver::resolve(did_url) {
                        Some(doc)
                    } else { None }
                },
                _ => None
            }
        },
        None => None,
    }
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
}
