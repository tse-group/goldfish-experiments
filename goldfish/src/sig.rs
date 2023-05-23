use base64::{engine::general_purpose, Engine as _};
// use cached::proc_macro::cached;
use rand::thread_rng;
use serde::{Deserialize, Serialize};

use crate::ghash;

pub trait Scheme {
    type Pk;
    type Sk;
    type Sig;

    fn new() -> Self;
    fn gen(&mut self) -> (Self::Sk, Self::Pk);
    fn sign(sk: &Self::Sk, m: &[u8]) -> Self::Sig;
    fn verify(pk: &Self::Pk, m: &[u8], sigma: &Self::Sig) -> bool;
}

pub struct MockScheme {
    last_id: u64,
}

impl Scheme for MockScheme {
    type Pk = u64;
    type Sk = u64;
    type Sig = (ghash::Ghash, u64);

    fn new() -> Self {
        Self { last_id: 10000 }
    }

    fn gen(&mut self) -> (Self::Sk, Self::Pk) {
        self.last_id += 1;
        (self.last_id, self.last_id)
    }

    fn sign(sk: &Self::Sk, m: &[u8]) -> Self::Sig {
        (ghash::Ghash::new(m), *sk)
    }

    fn verify(pk: &Self::Pk, m: &[u8], sigma: &Self::Sig) -> bool {
        sigma.0 == ghash::Ghash::new(m) && sigma.1 == *pk
    }
}

pub struct MilagroBlsScheme {}

// TODO TODO TODO: enable signature verification
// #[cached(sync_writes = true)]
// #[cached]
#[allow(unused_variables)]
fn milagro_bls_scheme_verify(
    pk: <MilagroBlsScheme as Scheme>::Pk,
    m: Vec<u8>,
    sigma: <MilagroBlsScheme as Scheme>::Sig,
) -> bool {
    // sigma.0.clone().unwrap().verify(&m, &pk.0) // TODO TODO TODO: enable signature verification
    true
}

impl Scheme for MilagroBlsScheme {
    type Pk = MilagroBlsSchemePk;
    type Sk = milagro_bls::SecretKey;
    type Sig = MilagroBlsSchemeSig;

    fn new() -> Self {
        Self {}
    }

    fn gen(&mut self) -> (Self::Sk, Self::Pk) {
        let sk = milagro_bls::SecretKey::random(&mut thread_rng());
        let pk = milagro_bls::PublicKey::from_secret_key(&sk);
        (sk, MilagroBlsSchemePk(pk))
    }

    fn sign(sk: &Self::Sk, m: &[u8]) -> Self::Sig {
        let sig = MilagroBlsSchemeSig(Some(milagro_bls::Signature::new(m, &sk)));
        sig
    }

    fn verify(pk: &Self::Pk, m: &[u8], sigma: &Self::Sig) -> bool {
        // sigma.0.clone().unwrap().verify(m, &pk.0)
        milagro_bls_scheme_verify(pk.clone(), m.to_vec(), sigma.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MilagroBlsSchemePk(milagro_bls::PublicKey);

impl std::hash::Hash for MilagroBlsSchemePk {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.clone().as_bytes().hash(state)
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    into = "MilagroBlsSchemeSigSerdeWrapper",
    from = "MilagroBlsSchemeSigSerdeWrapper"
)]
pub struct MilagroBlsSchemeSig(Option<milagro_bls::Signature>);

// #[cached]
// fn milagro_bls_scheme_sig_as_bytes_for_hashing(sig: MilagroBlsSchemeSig) -> [u8; 96] {
//     match sig.0 {
//         Some(ref sig) => sig.clone().as_bytes(),
//         None => [0; 96],
//     }
// }

impl MilagroBlsSchemeSig {
    // pub fn as_bytes_for_hashing(&self) -> [u8; 96] {
    //     milagro_bls_scheme_sig_as_bytes_for_hashing(self.clone())
    // }

    pub fn as_bytes_for_hashing(&self) -> [u8; 96] {
        match self.0 {
            Some(ref sig) => sig.clone().as_bytes(),
            None => [0; 96],
        }
    }

    // pub fn as_bytes_for_hashing(&self) -> [u8; 96] {
    //     match self.0 {
    //         Some(ref sig) => sig.clone().as_bytes(),
    //         // Some(ref sig) => milagro_bls_scheme_sig_as_bytes_for_hashing(*sig),
    //         // Some(ref sig) => unsafe { odds::raw_byte_repr(sig) }
    //         //     .to_vec()
    //         //     .try_into()
    //         //     .expect("incorrect length!"),
    //         None => [0; 96],
    //     }
    // }

    // pub fn as_bytes_for_hashing(&self) -> Vec<u8> {
    //     match self.0 {
    //         Some(ref sig) => unsafe { odds::raw_byte_repr(sig) }.to_vec(),
    //         None => [0; 96].to_vec(),
    //     }
    // }
}

impl std::fmt::Debug for MilagroBlsSchemeSig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if *self == Self::default() {
            return f.debug_tuple("S").field(&"Default").finish();
        } else {
            f.debug_tuple("S")
                .field(
                    &general_purpose::STANDARD_NO_PAD.encode(self.0.clone().unwrap().as_bytes())
                        [..10]
                        .to_string(),
                )
                .finish()
        }
    }
}

impl Default for MilagroBlsSchemeSig {
    fn default() -> Self {
        Self(None)
    }
}

// impl std::hash::Hash for MilagroBlsSchemeSig {
//     fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
//         self.0.clone().unwrap().as_bytes().hash(state)
//     }
// }

impl std::hash::Hash for MilagroBlsSchemeSig {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self.0 {
            Some(ref sig) => sig.clone().as_bytes().hash(state),
            None => [0; 96].hash(state),
        }
    }
}

// impl std::hash::Hash for MilagroBlsSchemeSig {
//     fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
//         match self.0 {
//             Some(ref sig) => unsafe { odds::raw_byte_repr(sig) }.to_vec().hash(state),
//             None => [0; 96].hash(state),
//         }
//     }
// }

/// https://github.com/serde-rs/bytes/issues/26#issuecomment-902550669
mod serde_bytes_array {
    use core::convert::TryInto;

    use serde::de::Error;
    use serde::{Deserializer, Serializer};

    /// This just specializes [`serde_bytes::serialize`] to `<T = [u8]>`.
    pub(crate) fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_bytes::serialize(bytes, serializer)
    }

    /// This takes the result of [`serde_bytes::deserialize`] from `[u8]` to `[u8; N]`.
    pub(crate) fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        let slice: &[u8] = serde_bytes::deserialize(deserializer)?;
        let array: [u8; N] = slice.try_into().map_err(|_| {
            let expected = format!("[u8; {}]", N);
            D::Error::invalid_length(slice.len(), &expected.as_str())
        })?;
        Ok(array)
    }
}

#[derive(Serialize, Deserialize)]
struct MilagroBlsSchemeSigSerdeWrapper {
    // default: bool,
    #[serde(with = "serde_bytes_array")]
    bytes: [u8; 96],
}

impl std::convert::From<MilagroBlsSchemeSig> for MilagroBlsSchemeSigSerdeWrapper {
    fn from(value: MilagroBlsSchemeSig) -> Self {
        if value.0.is_none() {
            Self {
                // default: true,
                bytes: [0; 96],
            }
        } else {
            Self {
                // default: false,
                bytes: value.0.unwrap().as_bytes(),
            }
        }
    }
}

impl std::convert::From<MilagroBlsSchemeSigSerdeWrapper> for MilagroBlsSchemeSig {
    fn from(value: MilagroBlsSchemeSigSerdeWrapper) -> Self {
        // if value.default {
        if value.bytes == [0; 96] {
            Self(None)
        } else {
            Self(Some(
                milagro_bls::Signature::from_bytes(&value.bytes).unwrap(),
            ))
        }
    }
}
