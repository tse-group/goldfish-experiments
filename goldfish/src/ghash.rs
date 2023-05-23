use base64::{engine::general_purpose, Engine as _};
use serde::{Deserialize, Serialize};
// use sha3::{Digest, Sha3_256};
use blake3;

// pub type Ghasher = Sha3_256;
pub type Ghasher = blake3::Hasher;

#[derive(Default, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub struct Ghash {
    ghash: [u8; 32],
}

impl Ghash {
    pub fn new(m: &[u8]) -> Self {
        let mut hasher = Ghasher::new();
        hasher.update(m);
        Self {
            ghash: hasher.finalize().into(),
        }
    }

    pub fn extract_first_u64(&self) -> u64 {
        u64::from_le_bytes(self.ghash[..8].try_into().unwrap())
    }

    pub fn as_slice(&self) -> [u8; 32] {
        self.ghash.clone().try_into().unwrap()
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.ghash
    }
}

impl std::fmt::Debug for Ghash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("H")
            .field(&general_purpose::STANDARD_NO_PAD.encode(&self.ghash)[..10].to_string())
            .finish()
    }
}

impl std::convert::From<Ghasher> for Ghash {
    fn from(value: Ghasher) -> Self {
        Self {
            ghash: value.finalize().into(),
        }
    }
}
