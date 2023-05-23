use crate::ghash;
use crate::{sig, sig::Scheme as _};

pub trait Scheme {
    type Pk;
    type Sk;
    type Pf;

    fn new() -> Self;
    fn gen(&mut self) -> (Self::Sk, Self::Pk);
    fn eval(sk: &Self::Sk, x: &[u8]) -> (u64, Self::Pf);
    fn verify(pk: &Self::Pk, x: &[u8], y: u64, pf: &Self::Pf) -> bool;
}

pub struct MockScheme {
    last_id: u64,
}

impl Scheme for MockScheme {
    type Pk = u64;
    type Sk = u64;
    type Pf = (u64, u64);

    fn new() -> Self {
        Self { last_id: 20000 }
    }

    fn gen(&mut self) -> (Self::Sk, Self::Pk) {
        self.last_id += 1;
        (self.last_id, self.last_id)
    }

    fn eval(sk: &Self::Sk, x: &[u8]) -> (u64, Self::Pf) {
        let mut hash_input = x.to_vec();
        hash_input.append(&mut sk.to_le_bytes().to_vec());
        let y = ghash::Ghash::new(&hash_input);
        let y = y.extract_first_u64();
        (y, (y, *sk))
    }

    fn verify(pk: &Self::Pk, x: &[u8], y: u64, pf: &Self::Pf) -> bool {
        let mut hash_input = x.to_vec();
        hash_input.append(&mut pk.to_le_bytes().to_vec());
        let y_ = ghash::Ghash::new(&hash_input);
        let y_ = y_.extract_first_u64();
        y == y_ && pf.0 == y_ && pf.1 == *pk
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MilagroBlsVrfScheme {}

impl Scheme for MilagroBlsVrfScheme {
    type Pk = <sig::MilagroBlsScheme as sig::Scheme>::Pk;
    type Sk = <sig::MilagroBlsScheme as sig::Scheme>::Sk;
    type Pf = <sig::MilagroBlsScheme as sig::Scheme>::Sig;

    fn new() -> Self {
        Self {}
    }

    fn gen(&mut self) -> (Self::Sk, Self::Pk) {
        sig::MilagroBlsScheme::new().gen()
    }

    fn eval(sk: &Self::Sk, x: &[u8]) -> (u64, Self::Pf) {
        let sig = sig::MilagroBlsScheme::sign(sk, x);
        let hash = ghash::Ghash::new(&bincode::serialize(&sig).unwrap());
        let y = hash.extract_first_u64();
        (y, sig)
    }

    fn verify(pk: &Self::Pk, x: &[u8], y: u64, pf: &Self::Pf) -> bool {
        let hash = ghash::Ghash::new(&bincode::serialize(&pf).unwrap());
        let y_ = hash.extract_first_u64();
        y == y_ && sig::MilagroBlsScheme::verify(pk, x, pf)
    }
}
