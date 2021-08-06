use std::fs;
use serde::Deserialize;
use web3::{Web3, contract::{Contract, Options}, ethabi::Token, transports::Http, types::Address};
use crate::Error;

pub const RINKEBY: &'static str = "./config/jolo_rinkeby.json";
pub const MAINNET: &'static str = "./config/jolo.json";

#[derive(Debug, Deserialize)]
struct JoloConfig {
    contract_address: String,
    provider_url: String,
    ipfs_endpoint: String,
}

pub struct JoloResolver {
    contract: Contract<Http>
}

impl JoloResolver {
    pub fn new(provider_address: &str, contract_address: &str) -> Result<Self, Error> {
        let http = Http::new(provider_address)?;
        let w3 = Web3::new(http);
        let c_address = Address::from_slice(&hex::decode(contract_address)?);
        Ok(Self {
            contract: Contract::from_json(
                w3.eth(),
                c_address,
                include_bytes!("./resources/jolo_token.json")
            )?
        })
    }

    pub async fn resolve_record(&self, did_url: String) -> Result<String, Error> {
        let url_token = Token::FixedBytes(hex::decode(did_url.trim_start_matches("did:jolo:"))?);
        let response: String = self.contract.query(
            "getRecord",
            (url_token,),
            None,
            Options::default(),
            None
        ).await?;
        if response.is_empty() {
            Err(Error::DidResolutionFailed)
        } else {
            Ok(response)
        }
    }
}

fn read_config(path: &str) -> Result<JoloConfig, Error> {
    Ok(serde_json::from_str::<JoloConfig>(&fs::read_to_string(path)?)?)
}

#[test]
fn rinkeby_config_loading() {
    let cfg = read_config(RINKEBY);
    assert!(cfg.is_ok());
}

#[test]
fn eth_address_from_str() {
    let cfg = read_config(RINKEBY).unwrap();
    let decoded = hex::decode(&cfg.contract_address);
    assert!(decoded.is_ok());
    let decoded_raw = decoded.unwrap();
    let address = Address::from_slice(&decoded_raw);
    println!("{:?}", address);
    assert!(true)
}

#[cfg(test)]
#[tokio::test]
async fn rinkeby_resolve() {
    let config = read_config(RINKEBY).unwrap();
    let test_user_did = "did:jolo:f334484858571199b681f6dfdd9ecd2f01df5b38f8379b3aaa89436c61fd1955";
    let resolver = JoloResolver::new(
        &config.provider_url,
        &config.contract_address
    );
    assert!(resolver.is_ok());
    let response = resolver.unwrap().resolve_record(test_user_did.into()).await;
    assert!(response.is_ok());
}
