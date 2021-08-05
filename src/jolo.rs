use std::fs;
use serde::Deserialize;
use web3::{Web3, contract::{Contract, Options, tokens::Tokenizable}, transports::Http, types::Address, ethabi::token::Token};
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
    pub fn new(address: &str) -> Result<Self, Error> {
        let http = Http::new(address)?;
        let w3 = Web3::new(http);
        Ok(Self {
            contract: Contract::from_json(
                w3.eth(),
                Address::from_token(Token::String(address.into()))?,
                include_bytes!("./resources/jolo_token.json")
            )?
        })
    }

    pub async fn resolve_record(&self, did_url: String) -> Result<String, Error> {
        let response: String = self.contract.query(
            "getRecord",
            (did_url,),
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
fn rinkeby_resolve_test() {
    let config = read_config(RINKEBY).unwrap();
    let test_user_did = "did:jolo:f334484858571199b681f6dfdd9ecd2f01df5b38f8379b3aaa89436c61fd1955";
    let resolver = JoloResolver::new(&config.contract_address);
    assert!(resolver.is_ok());
    let response = async_std::task::block_on(resolver.unwrap().resolve_record(test_user_did.into()));
    assert!(response.is_ok());
}
