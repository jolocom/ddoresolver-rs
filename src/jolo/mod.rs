use crate::{DdoResolver, Error};
mod ipfs;
#[cfg(feature = "registrar")]
use did_key::Document;
use ipfs::IpfsApiClient;
use serde::Deserialize;
use std::fs;
#[cfg(feature = "registrar")]
use web3::types::{H160, U256};
use web3::{
    contract::{Contract, Options},
    ethabi::Token,
    transports::Http,
    types::Address,
    Web3,
};

pub const RINKEBY: &'static str = "./config/jolo_rinkeby.json";
pub const MAINNET: &'static str = "./config/jolo.json";

#[derive(Debug, Deserialize)]
pub struct JoloConfig {
    contract_address: String,
    provider_url: String,
    ipfs_endpoint: String,
}

/// Instance of actual resolver
/// Implements `DdoResolver` trait for synchronous resolution
///  and `async_resolve()` method for asynchronous resolution
/// Can (and should) be used for cached/once instantiated
///  resolver for smoother performance.
/// Available ONLY with `jolo` feature
///
pub struct JoloResolver {
    contract: Contract<Http>,
    _w3: Web3<Http>,
    client: IpfsApiClient,
}

impl JoloResolver {
    /// Generic constructor, which takes all required inputs separately
    /// #Parameters
    /// `provider_address` - endpoint for Ethereum network communications.
    ///     URL for HTTP transport should be provided;
    /// `contract_address` - Jolo resolver Ethereum contract address;
    /// `ipfs_endpoint` - entry point for IPFS resolution.
    ///     base URL only! ### Example: https://ipfs.jolocom.com:443/
    ///
    pub fn new(
        provider_address: &str,
        contract_address: &str,
        ipfs_endpoint: &str,
    ) -> Result<Self, Error> {
        let http = Http::new(provider_address)?;
        let _w3 = Web3::new(http);
        let c_address = Address::from_slice(&hex::decode(contract_address)?);
        let ipfs_client = IpfsApiClient::new(ipfs_endpoint);
        Ok(Self {
            contract: Contract::from_json(
                _w3.eth(),
                c_address,
                include_bytes!("../resources/jolo_token.json"),
            )?,
            _w3,
            client: ipfs_client,
        })
    }

    /// Constructor, which takes path to a JSON config file
    ///  which contains `JoloConfig` information and uses it
    ///  with generic constructor.
    ///
    pub fn new_from_cfg(path: &str) -> Result<Self, Error> {
        let config = read_config(path)?;
        Self::new(
            &config.provider_url,
            &config.contract_address,
            &config.ipfs_endpoint,
        )
    }

    /// Resolver Ethereum record from jolocom contract
    /// #Parameters
    /// `did_url` - is DID url of identifier,
    ///  must start with "did:jolo:"
    ///  otherwise returns error: `Error::NotDidJolo`
    ///
    pub async fn resolve_record(&self, did_url: String) -> Result<String, Error> {
        if !did_url.starts_with("did::jolo:") && did_url.len() != 73 {
            return Err(Error::NotDidJolo);
        }
        let url_token = Token::FixedBytes(hex::decode(did_url.trim_start_matches("did:jolo:"))?);
        let response: String = self
            .contract
            .query("getRecord", (url_token,), None, Options::default(), None)
            .await?;
        if response.is_empty() {
            Err(Error::DidResolutionFailed)
        } else {
            Ok(response)
        }
    }

    /// Resolves DID document as an object string from IPFS
    /// #Parameters
    /// `hash` - hash returned by `resolve_record()` method;
    ///
    pub async fn get_ipfs_record(&self, hash: &str) -> Result<String, Error> {
        self.client.get(hash).await
    }

    #[cfg(feature = "registrar")]
    async fn store_ipfs_record(&self, document: String) -> Result<String, Error> {
        match self.client.add(document).await {
            Ok(res) => Ok(res),
            Err(e) => Err(Error::IpfsResponseError(e.to_string())),
        }
    }

    /// Full async resolver.
    /// Does the same as `DdoResolver::resolve()` but asynchronously
    /// #Parameters
    /// * `did_url` - is DID url of identifier,
    ///  must start with "did:jolo:"
    ///  otherwise returns error: `Error::NotDidJolo`
    ///
    pub async fn resolve_async(&self, did_url: &str) -> Result<did_key::Document, Error> {
        Ok(serde_json::from_str(
            &self
                .get_ipfs_record(&self.resolve_record(did_url.into()).await?)
                .await?,
        )?)
    }

    /// Full async registrar.
    /// Available with `registrar` feature only.
    /// #WARNING: works on mainnet only! (no pre-signing is supported)
    /// # Parameters
    /// * `document` - DID Document to be anchored
    /// * `account` - Ethereum account as raw bytes slice.
    /// panics if `account` is incorrect length
    ///
    #[cfg(feature = "registrar")]
    pub async fn register_async(&self, document: &Document, account: &[u8]) -> Result<(), Error> {
        if account.len() != 20 {
            return Err(Error::NotEthAddress);
        }
        // address of the caller
        let from = H160::from_slice(account);
        let serialized = serde_json::to_string(&document)?;
        let hash = Token::String(self.store_ipfs_record(serialized).await?);
        // let _d_hash = &hash.clone().into_string().unwrap().from_base58().unwrap();
        // let decoded = base64_url::decode(&document.id)?;
        let hex = hex::decode(&document.id)?;
        let token = Token::FixedBytes(hex);
        // Set gas limit and gas price for transaction
        let options = Options {
            gas: Some(U256::from_str_radix("0x493e0", 16).unwrap()),
            gas_price: Some(U256::from_str_radix("0x4e3b29200", 16).unwrap()),
            nonce: Some(self._w3.eth().transaction_count(from, None).await?),
            value: Some(U256::from_str_radix("0x00", 16).unwrap()),
            ..Options::default()
        };
        match self
            .contract
            .call("setRecord", (token, hash), from, options)
            .await
        {
            Ok(_) => Ok(()),
            Err(e) => Err(Error::W3ContractError(e)),
        }
    }
}

impl DdoResolver for JoloResolver {
    fn resolve(&self, did_url: &str) -> Result<did_key::Document, Error> {
        let rt = tokio::runtime::Runtime::new()?;
        let hash = rt.block_on(self.resolve_record(did_url.into()))?;
        let ddo_from_ipfs = rt.block_on(self.get_ipfs_record(&hash))?;
        Ok(serde_json::from_str(&ddo_from_ipfs)?)
    }
}

fn read_config(path: &str) -> Result<JoloConfig, Error> {
    Ok(serde_json::from_str::<JoloConfig>(&fs::read_to_string(
        path,
    )?)?)
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
    let test_user_did = "did:jolo:338a99de7bf54b4949590f4934d74b171bddf3812ddd92a60563b50d19f590bc";
    let resolver = JoloResolver::new(
        &config.provider_url,
        &config.contract_address,
        &config.ipfs_endpoint,
    );
    assert!(resolver.is_ok());

    let response = resolver.unwrap().resolve_record(test_user_did.into()).await;

    assert!(response.is_ok());
}

#[test]
fn jolo_doc_resolver() {
    let resolver = JoloResolver::new_from_cfg(RINKEBY).unwrap();

    let doc = resolver
        .resolve("did:jolo:e76fb4b4900e43891f613066b9afca366c6d22f7d87fc9f78a91515be24dfb21")
        .unwrap();

    use crate::DdoParser;
    let key = doc.find_public_key_for_curve("ED");
    assert!(key.is_some());
}

// Registrar tests
#[cfg(feature = "registrar")]
#[cfg(test)]
mod registrar_tests {
    use super::JoloResolver;
    use did_key::VerificationMethod;

    #[test]
    fn gas_conversion_test() {
        // panics if not succeeded
        let price = crate::jolo::U256::from_str_radix("0x4e3b29200", 16).unwrap();
        // panics if not succeeded
        let limit = crate::jolo::U256::from_str_radix("0x493e0", 16).unwrap();
        println!("price: {}, limit: {}", price, limit);
    }

    #[tokio::test]
    async fn registration_and_resolution_test() {
        let resolver = JoloResolver::new_from_cfg(super::RINKEBY).unwrap();
        let doc = did_key::Document {
            context: "https://www.w3.org/ns/did/v1".into(),
            id: "f334484858571199b681f6dfdd9ecd2f01df5b38f8379b3aaa89436c61fd1955".into(),
            assertion_method: None,
            authentication: None,
            capability_delegation: None,
            capability_invocation: None,
            key_agreement: None,
            verification_method: vec![VerificationMethod::default()],
        };
        let result = resolver
            .register_async(
                &doc,
                &hex::decode("c4b48901af7891d83ce83877e1f8fb4c81a94907").unwrap(),
            )
            .await;
        if result.is_err() {
            println!("{:?}", result);
        }
        assert!(result.is_ok());
        let resolve_result = resolver
            .resolve_async(&format!("did:jolo:{}", doc.id))
            .await;
        assert!(resolve_result.is_ok());
    }
}
