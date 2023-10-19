mod sha;
use ed25519_dalek::{Signer, SigningKey};
use merkletree::merkle::MerkleTree;
use merkletree::store::VecStore;
use rand::Rng;
use reqwest::get;
use serde::Deserialize;
use sha::TestSha256Hasher;

const BASE_URL: &str = "http://127.0.0.1:8000";

#[derive(Deserialize, Debug)]
struct Resp {
    root: [u8; 32],
    data: Vec<[u8; 32]>,
}

#[tokio::main]
async fn main() {
    for _ in 0..4 {
        // Generate random bytes to store on the server.
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();

        // Generate random private key.
        let signing_key = SigningKey::from_bytes(&rand::thread_rng().gen::<[u8; 32]>());
        // Sign the random bytes in order to store them.
        let signature = signing_key.sign(&random_bytes);
        // Send and store the bytes.
        get(format!(
            "{:}/save?bytes={:}&sig={:}&pk={:}",
            BASE_URL,
            hex::encode(random_bytes),
            hex::encode(signature.to_bytes()),
            hex::encode(signing_key.verifying_key().as_bytes())
        ))
        .await
        .unwrap();
    }
    let res = get(format!("{BASE_URL:}/get_root_and_data")).await.unwrap();
    let res: Resp = serde_json::from_str(&res.text().await.unwrap()).unwrap();
    assert_eq!(
        MerkleTree::<[u8; 32], TestSha256Hasher, VecStore<[u8; 32]>>::from_data(res.data).unwrap().root(),
        res.root,
        "Invalid merkle root for provided data"
    );
    println!("Valid state root")
}
