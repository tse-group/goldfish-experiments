use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::ghash;
use crate::goldfish_blockvote;
use crate::goldfish_type;
use crate::{sig, sig::Scheme};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Piece {
    Block(goldfish_blockvote::Block),
    Vote(goldfish_blockvote::Vote),
}

impl Piece {
    #[allow(dead_code)]
    pub fn digest(&self) -> goldfish_type::Hash {
        // ghash::Ghash::new(&bincode::serialize(&self).unwrap())
        let mut hasher = ghash::Ghasher::new();
        self.digest_hasher_update(&mut hasher);
        hasher.into()
    }

    pub fn digest_hasher_update(&self, hasher: &mut ghash::Ghasher) {
        hasher.update(b"piece");
        match self {
            Piece::Block(b) => {
                b.digest_hasher_update(hasher);
            }
            Piece::Vote(v) => {
                v.digest_hasher_update(hasher);
            }
        }
    }

    pub fn is_valid<C: goldfish_type::ValidationCache>(
        &self,
        lotteries: &goldfish_type::Lotteries,
        cache: &mut C,
        pki: &goldfish_type::Pki,
        bvset: &dyn goldfish_blockvote::BvSet,
    ) -> goldfish_type::ValidationResult {
        match self {
            Piece::Block(b) => b.is_valid(lotteries, cache, pki, bvset),
            Piece::Vote(v) => v.is_valid(lotteries, cache, pki, bvset),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    tips: HashSet<goldfish_type::Hash>,
    votes: HashSet<goldfish_type::Hash>,
    b: goldfish_blockvote::Block,
    sigma: <goldfish_type::Sigs as sig::Scheme>::Sig,
}

impl Proposal {
    #[allow(dead_code)]
    pub fn digest(&self) -> goldfish_type::Hash {
        // ghash::Ghash::new(&bincode::serialize(&self).unwrap())
        let mut hasher = ghash::Ghasher::new();
        self.digest_hasher_update(&mut hasher);
        hasher.into()
    }

    pub fn digest_hasher_update(&self, hasher: &mut ghash::Ghasher) {
        hasher.update(b"proposal");
        self.inner_digest_hasher_update(hasher);
        hasher.update(&self.sigma.as_bytes_for_hashing());
    }

    fn inner_digest(&self) -> goldfish_type::Hash {
        // ghash::Ghash::new(
        //     &bincode::serialize(&(
        //         "propose",
        //         self.tips.clone(),
        //         self.votes.clone(),
        //         self.b.clone(),
        //     ))
        //     .unwrap(),
        // )
        let mut hasher = ghash::Ghasher::new();
        self.inner_digest_hasher_update(&mut hasher);
        hasher.into()
    }

    fn inner_digest_hasher_update(&self, hasher: &mut ghash::Ghasher) {
        hasher.update(b"proposal");
        hasher.update(&self.tips.len().to_ne_bytes());
        hasher.update(&self.votes.len().to_ne_bytes());
        for t in &self.tips {
            hasher.update(t.as_bytes());
        }
        for v in &self.votes {
            hasher.update(v.as_bytes());
        }
        self.b.digest_hasher_update(hasher);
    }

    pub fn create(
        sk_sig: &<goldfish_type::Sigs as sig::Scheme>::Sk,
        bvtree: &goldfish_blockvote::BvTree,
        b: goldfish_blockvote::Block,
    ) -> Self {
        let mut p = Self {
            tips: bvtree.tip_digests_for_proposal(),
            votes: bvtree.vote_digests_for_proposal(),
            b,
            sigma: <goldfish_type::Sigs as sig::Scheme>::Sig::default(),
        };
        p.sigma = goldfish_type::Sigs::sign(sk_sig, &p.inner_digest().as_slice());
        p
    }

    pub fn is_valid<C: goldfish_type::ValidationCache>(
        &self,
        lotteries: &goldfish_type::Lotteries,
        cache: &mut C,
        pki: &goldfish_type::Pki,
        bvset: &dyn goldfish_blockvote::BvSet,
    ) -> goldfish_type::ValidationResult {
        if let Some(ret) = cache.get(&self.digest()) {
            return *ret;
        }

        let block_valid = self.b.is_valid(lotteries, cache, pki, bvset);
        if block_valid != goldfish_type::ValidationResult::Valid {
            if block_valid != goldfish_type::ValidationResult::Unknown {
                cache.insert(self.digest(), block_valid);
            }
            return block_valid;
        }

        let id = self.b.id();
        let (pk_sig, _pk_vrf) = pki.get(&id).unwrap();
        if !goldfish_type::Sigs::verify(pk_sig, &self.inner_digest().as_slice(), &self.sigma) {
            cache.insert(self.digest(), goldfish_type::ValidationResult::Invalid);
            return goldfish_type::ValidationResult::Invalid;
        }

        for hash_b in &self.tips {
            let b = bvset.get_block(hash_b.clone());
            if b == None {
                return goldfish_type::ValidationResult::Unknown;
            }
            let b = b.unwrap();
            let b_valid = b.is_valid(lotteries, cache, pki, bvset);
            if b_valid != goldfish_type::ValidationResult::Valid {
                if b_valid != goldfish_type::ValidationResult::Unknown {
                    cache.insert(self.digest(), b_valid);
                }
                return b_valid;
            }
            if b.slot() >= self.b.slot() {
                cache.insert(self.digest(), goldfish_type::ValidationResult::Invalid);
                return goldfish_type::ValidationResult::Invalid;
            }
        }

        for hash_v in &self.votes {
            let v = bvset.get_vote(hash_v.clone());
            if v == None {
                return goldfish_type::ValidationResult::Unknown;
            }
            let v = v.unwrap();
            let v_valid = v.is_valid(lotteries, cache, pki, bvset);
            if v_valid != goldfish_type::ValidationResult::Valid {
                if v_valid != goldfish_type::ValidationResult::Unknown {
                    cache.insert(self.digest(), v_valid);
                }
                return v_valid;
            }
            // if v.slot() >= self.b.slot() {
            if self.b.slot() == 0 || v.slot() != self.b.slot() - 1 {
                // can only include votes from the previous slot
                cache.insert(self.digest(), goldfish_type::ValidationResult::Invalid);
                return goldfish_type::ValidationResult::Invalid;
            }
        }

        cache.insert(self.digest(), goldfish_type::ValidationResult::Valid);
        goldfish_type::ValidationResult::Valid
    }

    pub fn prio(&self) -> u64 {
        self.b.prio()
    }

    pub fn slot(&self) -> goldfish_type::Slot {
        self.b.slot()
    }

    pub fn tips(&self) -> HashSet<goldfish_type::Hash> {
        self.tips.clone()
    }

    pub fn votes(&self) -> HashSet<goldfish_type::Hash> {
        self.votes.clone()
    }

    pub fn b(&self) -> goldfish_blockvote::Block {
        self.b.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Message {
    Piece(Piece),
    Proposal(Proposal),
}

impl Message {
    pub fn digest(&self) -> goldfish_type::Hash {
        // ghash::Ghash::new(&bincode::serialize(&self).unwrap())
        let mut hasher = ghash::Ghasher::new();
        self.digest_hasher_update(&mut hasher);
        hasher.into()
    }

    pub fn digest_hasher_update(&self, hasher: &mut ghash::Ghasher) {
        hasher.update(b"message");
        match self {
            Message::Piece(p) => p.digest_hasher_update(hasher),
            Message::Proposal(p) => p.digest_hasher_update(hasher),
        }
    }

    pub fn slot(&self) -> goldfish_type::Slot {
        match self {
            Message::Piece(p) => match p {
                Piece::Block(b) => b.slot(),
                Piece::Vote(v) => v.slot(),
            },
            Message::Proposal(p) => p.b.slot(),
        }
    }

    pub fn is_valid<C: goldfish_type::ValidationCache>(
        &self,
        lotteries: &goldfish_type::Lotteries,
        cache: &mut C,
        pki: &goldfish_type::Pki,
        bvset: &dyn goldfish_blockvote::BvSet,
    ) -> goldfish_type::ValidationResult {
        match self {
            Message::Piece(p) => p.is_valid(lotteries, cache, pki, bvset),
            Message::Proposal(p) => p.is_valid(lotteries, cache, pki, bvset),
        }
    }

    pub fn size(&self) -> usize {
        bincode::serialize(&self).unwrap().len()
    }
}
