use std::collections::HashMap;

use crate::ghash;
use crate::lottery;
use crate::sig;
use crate::vrf;

// pub type Sigs = sig::MockScheme;
// pub type Vrfs = vrf::MockScheme;
pub type Sigs = sig::MilagroBlsScheme;
pub type Vrfs = vrf::MilagroBlsVrfScheme;
pub type Hash = ghash::Ghash;

pub type Id = u64;
pub type Slot = <Lottery as lottery::Lottery>::Ticket;
pub type Ticket = (Id, Slot);

pub type Pki = HashMap<Id, (<Sigs as sig::Scheme>::Pk, <Vrfs as vrf::Scheme>::Pk)>;

pub type Lottery = lottery::VrfLottery<Vrfs>;

#[derive(Debug, Clone, Copy)]
pub struct Lotteries {
    pub block: Lottery,
    pub vote: Lottery,
}

impl Lotteries {
    pub fn new(block: Lottery, vote: Lottery) -> Self {
        Self { block, vote }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationResult {
    Invalid = 0,
    Valid = 1,
    Unknown = 2,
}

pub trait ValidationCache {
    fn get(&self, hash: &Hash) -> Option<&ValidationResult>;
    fn insert(&mut self, hash: Hash, result: ValidationResult);
}

impl ValidationCache for HashMap<Hash, ValidationResult> {
    fn get(&self, hash: &Hash) -> Option<&ValidationResult> {
        self.get(hash)
    }

    fn insert(&mut self, hash: Hash, result: ValidationResult) {
        self.insert(hash, result);
    }
}

pub struct RoValidationCache<'a, C> {
    cache: &'a C,
}

impl<'a, C> RoValidationCache<'a, C> {
    pub fn new(cache: &'a C) -> Self {
        Self { cache }
    }
}

impl<'a, C: ValidationCache> ValidationCache for RoValidationCache<'a, C> {
    fn get(&self, hash: &Hash) -> Option<&ValidationResult> {
        self.cache.get(hash)
    }

    fn insert(&mut self, _hash: Hash, _result: ValidationResult) {}
}

pub struct UnionValidationCache<'a, C1, C2> {
    ro_cache: &'a C1,
    rw_cache: &'a mut C2,
}

impl<'a, C1, C2> UnionValidationCache<'a, C1, C2> {
    pub fn new(ro_cache: &'a C1, rw_cache: &'a mut C2) -> Self {
        Self { ro_cache, rw_cache }
    }
}

impl<'a, C1: ValidationCache, C2: ValidationCache> ValidationCache
    for UnionValidationCache<'a, C1, C2>
{
    fn get(&self, hash: &Hash) -> Option<&ValidationResult> {
        self.rw_cache.get(hash).or_else(|| self.ro_cache.get(hash))
    }

    fn insert(&mut self, hash: Hash, result: ValidationResult) {
        self.rw_cache.insert(hash, result);
    }
}
