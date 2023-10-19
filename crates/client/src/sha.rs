use core::fmt;
use std::hash::Hasher;

use merkletree::hash::Algorithm;
use sha2::{Digest, Sha256};

pub struct TestSha256Hasher {
    engine: Sha256,
}

impl TestSha256Hasher {
    pub fn new() -> TestSha256Hasher {
        TestSha256Hasher { engine: Sha256::new() }
    }
}

impl fmt::Debug for TestSha256Hasher {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("Sha256Hasher")
    }
}

impl Default for TestSha256Hasher {
    fn default() -> Self {
        TestSha256Hasher::new()
    }
}

impl Hasher for TestSha256Hasher {
    fn finish(&self) -> u64 {
        unimplemented!("Hasher's contract (finish function is not used) is deliberately broken by design")
    }

    fn write(&mut self, bytes: &[u8]) {
        self.engine.update(bytes)
    }
}

impl Algorithm<[u8; 32]> for TestSha256Hasher {
    fn hash(&mut self) -> [u8; 32] {
        let mut result = <[u8; 32]>::default();
        let item_size = result.len();
        let hash_output = self.engine.clone().finalize().to_vec();
        self.engine.reset();
        if item_size < hash_output.len() {
            result.copy_from_slice(&hash_output.as_slice()[0..item_size]);
        } else {
            result.copy_from_slice(hash_output.as_slice())
        }
        result
    }
}
