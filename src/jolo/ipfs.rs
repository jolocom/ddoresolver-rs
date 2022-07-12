use crate::Error;
use reqwest::multipart::Form;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct IpfsAddResponse {
    name: String,
    hash: String,
    size: String,
}
pub struct IpfsApiClient {
    client: reqwest::Client,
    endpoint: String,
}

/// A simple IPFS API client implementation.
/// Uses the internal reqwest client to make requests and read / write data to a IPFS node.
impl IpfsApiClient {
    /// Creates new instance of IPFS API client.
    /// #Parameters
    /// `endpoint` - base URL of IPFS API endpoint.
    ///    ### Example: https://ipfs.jolocom.com:443/
    /// returns `IpfsApiClient` instance.
    ///
    pub fn new(endpoint: &str) -> Self {
        IpfsApiClient {
            client: reqwest::Client::new(),
            endpoint: endpoint.to_string(),
        }
    }

    /// Retrieve a file by hash using the HTTP API exposed by an IPFS node.
    /// #Parameters
    /// `hash` - hash of the file to retrieve.
    /// returns `Result` with `String` containing the file contents.
    ///
    pub async fn get(&self, hash: &str) -> Result<String, Error> {
        let url = format!("{}/api/v0/cat/{}", self.endpoint, hash);

        let response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|_| Error::IpfsResponseError("Failed to retrieve document".into()))?;

        let bytes = response
            .bytes()
            .await
            .map_err(|_| Error::IpfsResponseError("Failed to retrieve document".into()))?;

        Ok(String::from_utf8(bytes.as_ref().to_vec())?)
    }

    /// Add a file to IPFS using the HTTP API exposed by an IPFS node.
    /// #Parameters
    /// `document` - file to add to IPFS.
    /// returns `Result` containing the IPFS hash of the file.
    ///
    #[cfg(feature = "registrar")]
    pub async fn add(&self, document: String) -> Result<String, Error> {
        let url = format!("{}/api/v0/add?pin=true", self.endpoint);

        // The IPFS API expects the file to be uploaded as a multipart form.
        let form = Form::new().text("data", document);

        let response = self
            .client
            .post(&url)
            .multipart(form)
            .send()
            .await
            .map_err(|_| Error::IpfsResponseError("Failed to write document".into()))?;

        let bytes = response
            .bytes()
            .await
            .map_err(|_| Error::IpfsResponseError("Failed to parse response".into()))?;

        let parsed_response = serde_json::from_slice::<IpfsAddResponse>(&bytes)?;

        Ok(parsed_response.hash)
    }
}

#[cfg(test)]
mod ipfs_tests {
    use crate::jolo::JoloResolver;
    use crate::jolo::RINKEBY;

    #[tokio::test]
    async fn ipfs_resolve() {
        let ddo_hash = "Qma7TKfxrSx7SNMFMw8YvQBwsMLA1GebraG5NT8UzBTUAM";
        let resolver = JoloResolver::new_from_cfg(RINKEBY);
        assert!(resolver.is_ok());
        let ddo = resolver.unwrap().get_ipfs_record(ddo_hash).await;
        if ddo.is_err() {
            println!("{:?}", ddo);
        }
        assert!(ddo.is_ok());
    }

    #[tokio::test]
    async fn write_doc_to_ipfs_test() {
        let resolver = JoloResolver::new_from_cfg(RINKEBY).unwrap();
        let test_string = "Hello, world!";
        let hash = resolver
            .store_ipfs_record(test_string.into())
            .await
            .unwrap();

        assert_eq!(hash.len(), 46);
    }
}
