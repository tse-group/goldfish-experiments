use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};

use crate::ghash;
use crate::goldfish_message;
use crate::goldfish_type;
use crate::{lottery, lottery::Lottery};
use crate::{sig, sig::Scheme};

const BLOCK_SIZE: usize = 80_000;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Payload {
    graffiti: String,
    #[serde(with = "serde_big_array::BigArray")]
    data: [u8; BLOCK_SIZE],
}

impl Default for Payload {
    fn default() -> Self {
        Self {
            graffiti: String::new(),
            data: [0; BLOCK_SIZE],
        }
    }
}

impl Payload {
    fn digest_hasher_update(&self, hasher: &mut ghash::Ghasher) {
        hasher.update(b"payload");
        hasher.update(&self.data);
        hasher.update(&self.graffiti.as_bytes());
    }

    fn random_with_graffiti(graffiti: String) -> Self {
        let mut rng = rand::thread_rng();
        let mut data = [0; BLOCK_SIZE];
        rng.fill_bytes(&mut data);
        Self { graffiti, data }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Block {
    ticket: goldfish_type::Ticket,
    rho: <goldfish_type::Lottery as lottery::Lottery>::Opening,
    h: goldfish_type::Hash,
    payload: Payload,
    sigma: <goldfish_type::Sigs as sig::Scheme>::Sig,
}

impl Block {
    pub fn digest(&self) -> goldfish_type::Hash {
        // ghash::Ghash::new(&bincode::serialize(&self).unwrap())
        let mut hasher = ghash::Ghasher::new();
        self.digest_hasher_update(&mut hasher);
        hasher.into()
    }

    pub fn digest_hasher_update(&self, hasher: &mut ghash::Ghasher) {
        hasher.update(b"block");
        hasher.update(&self.ticket.0.to_ne_bytes());
        hasher.update(&self.ticket.1.to_ne_bytes());
        hasher.update(&self.rho.0.to_ne_bytes());
        hasher.update(&self.rho.1.as_bytes_for_hashing());
        self.inner_digest_hasher_update(hasher);
        hasher.update(&self.sigma.as_bytes_for_hashing());
    }

    fn inner_digest(&self) -> goldfish_type::Hash {
        // ghash::Ghash::new(
        //     &bincode::serialize(&("block", self.h.clone(), self.txs.clone())).unwrap(),
        // )
        let mut hasher = ghash::Ghasher::new();
        self.inner_digest_hasher_update(&mut hasher);
        hasher.into()
    }

    fn inner_digest_hasher_update(&self, hasher: &mut ghash::Ghasher) {
        hasher.update(b"block");
        hasher.update(&self.h.as_bytes());
        self.payload.digest_hasher_update(hasher);
    }

    pub fn create(
        sk_sig: &<goldfish_type::Sigs as sig::Scheme>::Sk,
        ticket: goldfish_type::Ticket,
        rho: <goldfish_type::Lottery as lottery::Lottery>::Opening,
        h: goldfish_type::Hash,
        txs: String,
    ) -> Self {
        let mut b = Self {
            ticket,
            rho,
            h,
            payload: Payload::random_with_graffiti(txs),
            sigma: <goldfish_type::Sigs as sig::Scheme>::Sig::default(),
        };
        b.sigma = goldfish_type::Sigs::sign(sk_sig, &b.inner_digest().as_slice());
        b
    }

    pub fn is_valid<C: goldfish_type::ValidationCache>(
        &self,
        lotteries: &goldfish_type::Lotteries,
        cache: &mut C,
        pki: &goldfish_type::Pki,
        bvset: &dyn BvSet,
    ) -> goldfish_type::ValidationResult {
        if let Some(ret) = cache.get(&self.digest()) {
            return *ret;
        }

        if *self == Self::default() {
            cache.insert(self.digest(), goldfish_type::ValidationResult::Valid);
            return goldfish_type::ValidationResult::Valid;
        }

        let b_parent = bvset.get_block(self.h.clone());
        if b_parent == None {
            return goldfish_type::ValidationResult::Unknown;
        }
        let b_parent = b_parent.unwrap();
        assert!(
            b_parent.is_valid(lotteries, cache, pki, bvset)
                == goldfish_type::ValidationResult::Valid
        );

        let id = self.ticket.0;
        let (pk_sig, pk_vrf) = pki.get(&id).unwrap();
        if lotteries.block.is_winning(pk_vrf, self.ticket.1, &self.rho)
            && goldfish_type::Sigs::verify(pk_sig, &self.inner_digest().as_slice(), &self.sigma)
            && b_parent.is_valid(lotteries, cache, pki, bvset)
                == goldfish_type::ValidationResult::Valid
            && self.ticket.1 > b_parent.ticket.1
        {
            cache.insert(self.digest(), goldfish_type::ValidationResult::Valid);
            return goldfish_type::ValidationResult::Valid;
        }

        cache.insert(self.digest(), goldfish_type::ValidationResult::Invalid);
        goldfish_type::ValidationResult::Invalid
    }

    pub fn slot(&self) -> goldfish_type::Slot {
        self.ticket.1
    }

    pub fn id(&self) -> goldfish_type::Id {
        self.ticket.0
    }

    pub fn prio(&self) -> u64 {
        goldfish_type::Lottery::prio(&self.rho)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Vote {
    ticket: goldfish_type::Ticket,
    rho: <goldfish_type::Lottery as lottery::Lottery>::Opening,
    h: goldfish_type::Hash,
    sigma: <goldfish_type::Sigs as sig::Scheme>::Sig,
}

impl Vote {
    pub fn digest(&self) -> goldfish_type::Hash {
        // ghash::Ghash::new(&bincode::serialize(self).unwrap())
        let mut hasher = ghash::Ghasher::new();
        self.digest_hasher_update(&mut hasher);
        hasher.into()
    }

    pub fn digest_hasher_update(&self, hasher: &mut ghash::Ghasher) {
        hasher.update(b"vote");
        hasher.update(&self.ticket.0.to_ne_bytes());
        hasher.update(&self.ticket.1.to_ne_bytes());
        hasher.update(&self.rho.0.to_ne_bytes());
        hasher.update(&self.rho.1.as_bytes_for_hashing());
        // hasher.update(&self.h.as_bytes());
        self.inner_digest_hasher_update(hasher);
        hasher.update(&self.sigma.as_bytes_for_hashing());
    }

    fn inner_digest(&self) -> goldfish_type::Hash {
        // ghash::Ghash::new(&bincode::serialize(&("vote", self.h.clone())).unwrap())
        let mut hasher = ghash::Ghasher::new();
        self.inner_digest_hasher_update(&mut hasher);
        hasher.into()
    }

    fn inner_digest_hasher_update(&self, hasher: &mut ghash::Ghasher) {
        hasher.update(b"vote");
        hasher.update(&self.h.as_bytes());
    }

    pub fn create(
        sk_sig: &<goldfish_type::Sigs as sig::Scheme>::Sk,
        ticket: goldfish_type::Ticket,
        rho: <goldfish_type::Lottery as lottery::Lottery>::Opening,
        h: goldfish_type::Hash,
    ) -> Self {
        let mut v = Self {
            ticket,
            rho,
            h,
            sigma: <goldfish_type::Sigs as sig::Scheme>::Sig::default(),
        };
        v.sigma = goldfish_type::Sigs::sign(sk_sig, &v.inner_digest().as_slice());
        v
    }

    pub fn is_valid<C: goldfish_type::ValidationCache>(
        &self,
        lotteries: &goldfish_type::Lotteries,
        cache: &mut C,
        pki: &goldfish_type::Pki,
        bvset: &dyn BvSet,
    ) -> goldfish_type::ValidationResult {
        if let Some(ret) = cache.get(&self.digest()) {
            return *ret;
        }

        let b_target = bvset.get_block(self.h.clone());
        if b_target == None {
            return goldfish_type::ValidationResult::Unknown;
        }
        let b_target = b_target.unwrap();
        assert!(
            b_target.is_valid(lotteries, cache, pki, bvset)
                == goldfish_type::ValidationResult::Valid
        );

        let id = self.ticket.0;
        let (pk_sig, pk_vrf) = pki.get(&id).unwrap();
        if lotteries.vote.is_winning(pk_vrf, self.ticket.1, &self.rho)
            && goldfish_type::Sigs::verify(pk_sig, &self.inner_digest().as_slice(), &self.sigma)
            && b_target.is_valid(lotteries, cache, pki, bvset)
                == goldfish_type::ValidationResult::Valid
            && self.ticket.1 >= b_target.ticket.1
        {
            cache.insert(self.digest(), goldfish_type::ValidationResult::Valid);
            return goldfish_type::ValidationResult::Valid;
        }

        cache.insert(self.digest(), goldfish_type::ValidationResult::Invalid);
        goldfish_type::ValidationResult::Invalid
    }

    pub fn slot(&self) -> goldfish_type::Slot {
        self.ticket.1
    }

    #[allow(dead_code)]
    pub fn id(&self) -> goldfish_type::Id {
        self.ticket.0
    }
}

pub trait BvSet {
    fn get_block(&self, h: goldfish_type::Hash) -> Option<Block>;
    fn get_vote(&self, h: goldfish_type::Hash) -> Option<Vote>;
}

#[derive(Debug, Clone, PartialEq)]
pub struct BvTree {
    blocks: HashMap<goldfish_type::Hash, Block>,
    votes: HashMap<goldfish_type::Hash, Vote>,
    votecount: HashMap<goldfish_type::Hash, HashSet<(goldfish_type::Id, goldfish_type::Slot)>>,
    children: HashMap<goldfish_type::Hash, HashSet<goldfish_type::Hash>>,
    tips: HashSet<goldfish_type::Hash>,
}

impl Default for BvTree {
    fn default() -> Self {
        let b0 = Block::default();
        BvTree {
            blocks: HashMap::from([(b0.digest(), b0.clone())]),
            votes: HashMap::new(),
            votecount: HashMap::from([(b0.digest(), HashSet::new())]),
            children: HashMap::from([(b0.digest(), HashSet::new())]),
            tips: HashSet::from([b0.digest()]),
        }
    }
}

impl BvSet for BvTree {
    fn get_block(&self, h: goldfish_type::Hash) -> Option<Block> {
        self.blocks.get(&h).cloned()
    }

    fn get_vote(&self, h: goldfish_type::Hash) -> Option<Vote> {
        self.votes.get(&h).cloned()
    }
}

impl BvTree {
    pub fn tip_digests_for_proposal(&self) -> HashSet<goldfish_type::Hash> {
        self.tips.clone()
    }

    pub fn vote_digests_for_proposal(&self) -> HashSet<goldfish_type::Hash> {
        self.votes.keys().cloned().collect()
    }

    pub fn insert_block(&mut self, b: &Block) {
        self.blocks.insert(b.digest(), b.clone());
        self.votecount.insert(b.digest(), HashSet::new());
        self.children.insert(b.digest(), HashSet::new());
        let b_parent_children = self.children.get_mut(&b.h).unwrap();
        b_parent_children.insert(b.digest());
        self.tips.remove(&b.h);
        self.tips.insert(b.digest());
    }

    pub fn merge<C: goldfish_type::ValidationCache>(
        &mut self,
        lotteries: &goldfish_type::Lotteries,
        cache: &mut C,
        pki: &goldfish_type::Pki,
        buffer_blocks: &mut HashMap<goldfish_type::Hash, Block>,
        buffer_votes: &mut HashMap<goldfish_type::Hash, Vote>,
        proposal: Option<&goldfish_message::Proposal>,
    ) {
        let mut try_to_merge = VecDeque::new();
        match proposal {
            None => {
                try_to_merge.extend(buffer_blocks.keys().cloned());
            }

            Some(p) => {
                let bvset = BufferAugmentedBvTree::new(self, buffer_blocks, buffer_votes);
                for h in p.tips() {
                    let mut h_ = h;
                    while !try_to_merge.contains(&h_) && h_ != Block::default().digest() {
                        try_to_merge.push_back(h_.clone());
                        let b = bvset.get_block(h_).unwrap();
                        h_ = b.h.clone();
                    }
                }
            }
        }

        while try_to_merge.len() > 0 {
            let k = try_to_merge.pop_front().unwrap();

            if self.blocks.contains_key(&k) {
                // block might have arrived to buffer as a "piece"
                // due to separate relaying of proposed blocks
                // assert!(!buffer_blocks.contains_key(&k));
                buffer_blocks.remove(&k);
                continue;
            }

            let b = buffer_blocks.remove(&k).unwrap();

            let b_is_valid = b.is_valid(lotteries, cache, pki, self);
            assert!(b_is_valid != goldfish_type::ValidationResult::Invalid);

            match b_is_valid {
                goldfish_type::ValidationResult::Valid => {
                    self.insert_block(&b);
                }
                goldfish_type::ValidationResult::Invalid => {
                    assert!(b_is_valid != goldfish_type::ValidationResult::Invalid);
                }
                goldfish_type::ValidationResult::Unknown => {
                    try_to_merge.push_back(k.clone());
                    buffer_blocks.insert(k, b);
                }
            }
        }

        if let Some(p) = proposal {
            let b = p.b();
            assert!(
                b.is_valid(lotteries, cache, pki, self) == goldfish_type::ValidationResult::Valid
            );
            self.insert_block(&b);
        }

        for (_, v) in buffer_votes.drain_filter(|k, _v| match proposal {
            None => true,
            Some(p) => p.votes().contains(&k),
        }) {
            let v_is_valid = v.is_valid(lotteries, cache, pki, self);
            assert!(v_is_valid == goldfish_type::ValidationResult::Valid);
            self.votes.insert(v.digest(), v.clone());

            let mut b_target_hash = v.h;
            loop {
                let b_target_votecount = self.votecount.get_mut(&b_target_hash).unwrap();
                b_target_votecount.insert(v.ticket);

                if b_target_hash == Block::default().digest() {
                    break;
                }

                let b_target = self.blocks.get(&b_target_hash).unwrap();
                b_target_hash = b_target.h.clone();
            }
        }
    }

    pub fn expire_votes_before(&mut self, t: isize) {
        self.votes.retain(|_, v| (v.slot() as isize) >= t);
        assert!(
            self.votes
                .iter()
                .filter(|(_, v)| (v.slot() as isize) > t + 1)
                .count()
                == 0
        );
        for (_, votes) in self.votecount.iter_mut() {
            votes.retain(|(_, t_)| (*t_ as isize) >= t);
            assert!(
                votes
                    .iter()
                    .filter(|(_, t_)| (*t_ as isize) > t + 1)
                    .count()
                    == 0
            );
        }
    }

    pub fn ghost_eph(&self, t: isize, min_votes: usize) -> goldfish_type::Hash {
        let mut h = &Block::default().digest();
        while self.children.get(&h).unwrap().len() > 0 {
            let (h_, cnt) = self
                .children
                .get(&h)
                .unwrap()
                .iter()
                .map(|c| {
                    (
                        c,
                        self.votecount
                            .get(c)
                            .unwrap()
                            .iter()
                            .filter(|(_id, t_)| t == (*t_ as isize))
                            .count(),
                    )
                })
                .max_by_key(|(_c, count)| *count)
                .unwrap();

            if cnt < min_votes {
                break;
            }

            h = h_;
        }
        h.clone()
    }

    pub fn get_block_height(&self, h: &goldfish_type::Hash) -> usize {
        let mut h_ = h;
        let mut height = 0;
        while h_ != &Block::default().digest() {
            height += 1;
            let b = self.blocks.get(h_).unwrap();
            h_ = &b.h;
        }
        height
    }

    pub fn truncate_back_to_slot(&self, h: &goldfish_type::Hash, t: isize) -> goldfish_type::Hash {
        let mut h_ = h;
        let mut b = self.blocks.get(h_).unwrap();
        while h_ != &Block::default().digest() && (b.ticket.1 as isize) > t {
            h_ = &b.h;
            b = self.blocks.get(h_).unwrap();
        }
        h_.clone()
    }

    //     kappa: usize) -> goldfish_type::Hash {
    //     let mut h_ = h;
    //     let mut height = 0;
    //     while h_ != &Block::default().digest() && height < kappa {
    //         height += 1;
    //         let b = self.blocks.get(h_).unwrap();
    //         h_ = &b.h;
    //     }
    //     h_.clone()
    // }

    #[allow(dead_code)]
    pub fn dump_dotfile(&self) -> String {
        fn export_digest(d: ghash::Ghash) -> String {
            return format!("{:?}", d)
                .replace("+", "")
                .replace("/", "")
                .replace("(", "")
                .replace(")", "")
                .replace("\"", "");
        }
        let mut v: String = "digraph G {\n  rankdir=BT;\n  style=filled;\n  color=lightgrey;\n  node [shape=box,style=filled,color=white];\n".to_string();
        for b in self.blocks.values() {
            v = format!(
                "{}  b_{} [label=\"{}\\n{}\"];\n",
                v,
                export_digest(b.digest()),
                format!("{:?}", b.digest()).replace("\"", ""),
                b.payload.graffiti.replace("\"", "")
            );
        }
        for b in self.blocks.values() {
            if b.digest() != Block::default().digest() {
                v = format!(
                    "{}  b_{} -> b_{};\n",
                    v,
                    export_digest(b.digest()),
                    export_digest(b.h.clone())
                );
            }
        }
        for v_ in self.votes.values() {
            v = format!(
                "{}  v_{} [label=\"id={} t={}\"];\n",
                v,
                export_digest(v_.digest()),
                v_.ticket.0,
                v_.ticket.1,
            );
            v = format!(
                "{}  v_{} -> b_{};\n",
                v,
                export_digest(v_.digest()),
                export_digest(v_.h.clone())
            );
        }
        v = format!("{}}}\n", v);
        v
    }
}

#[derive(Debug)]
pub struct BufferAugmentedBvTree<'a> {
    bvtree: &'a BvTree,
    dangling_blocks: &'a HashMap<goldfish_type::Hash, Block>,
    dangling_votes: &'a HashMap<goldfish_type::Hash, Vote>,
}

impl<'a> BvSet for BufferAugmentedBvTree<'a> {
    fn get_block(&self, h: goldfish_type::Hash) -> Option<Block> {
        if let Some(b) = self.bvtree.get_block(h.clone()) {
            return Some(b.clone());
        }

        self.dangling_blocks.get(&h).cloned()
    }

    fn get_vote(&self, h: goldfish_type::Hash) -> Option<Vote> {
        if let Some(v) = self.bvtree.get_vote(h.clone()) {
            return Some(v.clone());
        }

        self.dangling_votes.get(&h).cloned()
    }
}

impl<'a> BufferAugmentedBvTree<'a> {
    pub fn new(
        bvtree: &'a BvTree,
        dangling_blocks: &'a HashMap<goldfish_type::Hash, Block>,
        dangling_votes: &'a HashMap<goldfish_type::Hash, Vote>,
    ) -> Self {
        BufferAugmentedBvTree {
            bvtree,
            dangling_blocks,
            dangling_votes,
        }
    }
}
