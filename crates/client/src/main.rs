mod sha;

use ed25519_dalek::{Signer, SigningKey};
use merkletree::merkle::MerkleTree;
use merkletree::store::VecStore;
use rand::Rng;
use reqwest::get;
use serde::Deserialize;
use sha::TestSha256Hasher;

const BASE_URL: &str = "http://127.0.0.1:8000";

/// Type to deserialize the response of the server.
#[derive(Deserialize)]
struct RootData {
    root: [u8; 32],
    data: Vec<[u8; 32]>,
}

/// Type to deserialize the response of the server.
#[derive(Deserialize)]
struct Root {
    root: [u8; 32],
}

#[tokio::main]
async fn main() {
    let mut data = vec![];
    for _ in 0..4 {
        // Generate random bytes to store on the server.
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();
        data.push(random_bytes);
        // Generate random private key.
        let signing_key = SigningKey::from_bytes(&rand::thread_rng().gen::<[u8; 32]>());
        // Sign the random bytes in order to store them.
        let signature = signing_key.sign(&random_bytes);
        // Send and store the bytes.
        println!("Sending bytes to store");
        get(format!(
            "{:}/save?bytes={:}&sig={:}&pk={:}",
            BASE_URL,
            hex::encode(random_bytes),
            hex::encode(signature.to_bytes()),
            hex::encode(signing_key.verifying_key().as_bytes())
        ))
        .await
        .expect("Failed to store the bytes");
    }
    println!("Constructing a merkle tree from the data sent");
    let local_merkle_tree = MerkleTree::<[u8; 32], TestSha256Hasher, VecStore<[u8; 32]>>::from_data(data)
        .expect("Failed to build local merkle tree");

    // Get the merkle root and verify the integrity of the data.
    println!("Fetching the remote merkle root");
    let root_res = get(format!("{BASE_URL:}/get_root")).await.expect("Failed to fetch the merkle root");
    let root: Root = serde_json::from_str(&root_res.text().await.expect("Failed to get the text from the response"))
        .expect("Failed to deserialize the response");
    assert_eq!(local_merkle_tree.root(), root.root, "Remote data is corrupted");
    println!("Remote data isn't corrupted");

    // Get the merkle root and the leaves of the tree.
    println!("Getting the state root and data");
    let root_data_res =
        get(format!("{BASE_URL:}/get_root_and_data")).await.expect("Failed to fetch the proof and data");
    let root_data: RootData =
        serde_json::from_str(&root_data_res.text().await.expect("Failed to get the text from the response"))
            .expect("Failed to deserialize the response");
    // Verify that the merkle root is valid.
    println!("Verifying the state root against the data provided");
    let remote_merkle_tree =
        MerkleTree::<[u8; 32], TestSha256Hasher, VecStore<[u8; 32]>>::from_data(root_data.data).unwrap();
    assert_eq!(remote_merkle_tree.root(), root_data.root, "Invalid merkle root for provided data");
    println!("Valid state root");
}
