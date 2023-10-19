mod sha;

use std::cmp::min;
use std::sync::{Mutex, RwLock};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use lazy_static::lazy_static;
use merkletree::merkle::MerkleTree;
use merkletree::store::VecStore;
use merkletree::{self};
use rocket::{get, launch, routes};
use serde::Serialize;
use sha::TestSha256Hasher;

lazy_static! {
    /// Holds all the data stored on the server.
    static ref DATA: Mutex<Vec<[u8; 32]>> = Mutex::from(vec![]);
    /// Once there is enough data constructs a merkle tree from it or updates it.
    static ref TREE: RwLock<MerkleTree<[u8; 32], TestSha256Hasher, VecStore<[u8; 32]>>> = RwLock::new(
        MerkleTree::<[u8; 32], TestSha256Hasher, VecStore<[u8; 32]>>::from_data(vec![[0; 32], [0; 32]]).unwrap(),
    );
}

/// Convert a &[u8] to a fixed size [u8; 32]. Pads the slice with 0s if it's too small and ignore
/// the other bytes if it's too big.
///
/// # Argument
///
/// * `bytes` - The slice to convert to a fixed length array.
///
/// Returns
///
/// * `[u8; 32]` - The fixed length byte slice.
fn convert_to_fixed_array(bytes: &[u8]) -> [u8; 32] {
    // Convert &[u8] into [u8; 32].
    let mut buff = [0u8; 32];
    // Fill the empty buffer with at most 32 bytes from what is sent.
    buff[..min(bytes.len(), 32)].copy_from_slice(&bytes[..min(32, bytes.len())]);
    buff
}

/// Saves the bytes sent to this endpoint (saves at most 32 bytes). In order to have the data
/// accepted a signature is needed. If there is enough data it'll create a merkle tree from the
/// data.
///
/// # Arguments
///
/// * `bytes` - The bytes to save.
/// * `sig` - The signature of the bytes.
/// * `pk` - The public key of the signer.
///
/// # Panics
///
/// Panics if there is an internal problem in the server (mostly due to shared variable).
///
/// # Returns
///
/// * `String` - Contains either the error that happened during the run or the leaf index if
///   everything went well.
#[get("/save?<bytes>&<sig>&<pk>")]
fn save(bytes: &[u8], sig: &str, pk: &str) -> String {
    // Sig verification
    // Decode the hex string into bytes.
    let sig = match hex::decode(sig) {
        Ok(sig) => sig,
        Err(e) => return e.to_string(),
    };
    // Create a signature object from the signature string.
    let sig = match Signature::from_slice(&sig) {
        Ok(sig) => sig,
        Err(e) => return e.to_string(),
    };

    // Decode the hex string into bytes.
    let pk = match hex::decode(pk) {
        Ok(pk) => pk,
        Err(e) => return e.to_string(),
    };
    // Create a public key object from the public key string.
    let pk = match VerifyingKey::from_bytes(&convert_to_fixed_array(&pk)) {
        Ok(pk) => pk,
        Err(e) => return e.to_string(),
    };

    // Decode the hex string into bytes.
    let bytes = match hex::decode(bytes) {
        Ok(bytes) => bytes,
        Err(e) => return e.to_string(),
    };
    // Verify the signature against the bytes sent.
    match pk.verify(&bytes, &sig) {
        Ok(_) => (),
        Err(e) => return e.to_string(),
    };

    // Push the bytes into the data vec.
    DATA.lock().expect("Failed to lock data to push new bytes").push(convert_to_fixed_array(&bytes));
    // Get the length in a variable to avoid duplicating the work.
    let data_len = DATA.lock().expect("Failed to lock data to get the length").len();
    // Check if there is enough leaves to create a merkle tree.
    if data_len.is_power_of_two() && data_len != 1 {
        // Create the merkle tree from the data available.
        let new_tree =
            MerkleTree::from_data(DATA.lock().expect("Failed to lock data to construct the merkle tree").iter())
                .expect("Failed to create merkle tree");
        println!("{:#?}", new_tree);
        // Get the old tree.
        let mut v = TREE.write().expect("Failed to write the merkle tree");
        // Update the tree.
        *v = new_tree;
    }
    // Index of the new leaf.
    (data_len + 2).to_string()
}

/// Type to serialize the response of the endpoint.
#[derive(Serialize)]
struct RootData {
    root: [u8; 32],
    data: Vec<[u8; 32]>,
}

/// Returns the Merkle root and all the leaves data.
///
/// # Panics
///
/// Panics if it fails to lock the data vec.
///
/// # Returns
///
/// * `String` - Json serialization of the root and the data.
#[get("/get_root_and_data")]
fn get_root_and_data() -> String {
    let tree = TREE.read().expect("Failed to read the merkle tree");
    serde_json::to_string(&RootData {
        root: tree.root(),
        data: DATA
            .lock()
            .expect("Failed to lock data to retrive the committed data")
            .iter()
            .take(tree.leafs())
            .cloned()
            .collect(),
    })
    .unwrap_or(String::from("Failed to stringify the response"))
}

/// Type to serialize the response of the endpoint.
#[derive(Serialize)]
struct Root {
    root: [u8; 32],
}
/// Returns the merkle root of the server's merkle tree.
///
/// # Panic
///
/// Panics if it fails to read the tree or to serialize the root.
///
/// # Returns
///
/// * `String` - Json serialization of the merkle root.
#[get("/get_root")]
fn get_root() -> String {
    let root = TREE.read().expect("Failed to read the tree").root();
    serde_json::to_string(&Root { root }).unwrap_or(String::from("Failed to stringify the response"))
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![save, get_root_and_data, get_root])
}
