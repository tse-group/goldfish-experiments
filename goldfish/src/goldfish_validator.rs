use log;
use serde::{Deserialize, Serialize};
use serde_with::with_prefix;
use std::collections::{HashMap, HashSet, VecDeque};

use crate::goldfish_blockvote;
use crate::goldfish_blockvote::BvSet as _;
use crate::goldfish_message;
use crate::goldfish_type;
use crate::lottery::Lottery as _;
use crate::network;
use crate::sig;
use crate::vrf;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct LedgerStats {
    pub length: usize,
    pub age: goldfish_type::Slot,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ValidatorLedgerStats {
    #[serde(flatten, with = "prefix_ledger_best")]
    pub ledger_best: LedgerStats,
    #[serde(flatten, with = "prefix_ledger_fast")]
    pub ledger_fast: LedgerStats,
    #[serde(flatten, with = "prefix_ledger_slow")]
    pub ledger_slow: LedgerStats,
}

with_prefix!(prefix_ledger_best "ledger_best_");
with_prefix!(prefix_ledger_fast "ledger_fast_");
with_prefix!(prefix_ledger_slow "ledger_slow_");

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ValidatorDaStats {
    pub status: DaValidatorSleepStatus,
}

pub trait HonestValidator {
    fn step(
        &mut self,
        lotteries: &goldfish_type::Lotteries,
        r: usize,
        inboxes: &mut Vec<network::SimulationInbox>,
        my_inbox: usize,
    );
}

#[derive(Debug)]
pub struct Validator {
    id: goldfish_type::Id,
    sk_sig: <goldfish_type::Sigs as sig::Scheme>::Sk,
    sk_vrf: <goldfish_type::Vrfs as vrf::Scheme>::Sk,
    pki: goldfish_type::Pki,
    bvtree: goldfish_blockvote::BvTree,
    limbo: VecDeque<goldfish_message::Message>,
    msgs_relayed: HashSet<goldfish_type::Hash>,
    buffer_blocks: HashMap<goldfish_type::Hash, goldfish_blockvote::Block>,
    buffer_votes: HashMap<goldfish_type::Hash, goldfish_blockvote::Vote>,
    buffer_proposals: Vec<goldfish_message::Proposal>,
    confirm_slow_kappa: usize,
    confirm_fast_eps: f64,
    validation_cache: HashMap<goldfish_type::Hash, goldfish_type::ValidationResult>,
    tip_fast: goldfish_type::Hash,
    tip_slow: goldfish_type::Hash,
    tip_best: goldfish_type::Hash,
    stats: HashMap<usize, ValidatorLedgerStats>,
}

impl Validator {
    pub fn new(
        id: goldfish_type::Id,
        sk_sig: <goldfish_type::Sigs as sig::Scheme>::Sk,
        sk_vrf: <goldfish_type::Vrfs as vrf::Scheme>::Sk,
        pki: goldfish_type::Pki,
        confirm_slow_kappa: usize,
        confirm_fast_eps: f64,
    ) -> Self {
        Self {
            id,
            sk_sig,
            sk_vrf,
            pki,
            bvtree: goldfish_blockvote::BvTree::default(),
            limbo: VecDeque::new(),
            msgs_relayed: HashSet::new(),
            buffer_blocks: HashMap::new(),
            buffer_votes: HashMap::new(),
            buffer_proposals: Vec::new(),
            confirm_slow_kappa,
            confirm_fast_eps,
            validation_cache: HashMap::new(),
            tip_fast: goldfish_blockvote::Block::default().digest(),
            tip_slow: goldfish_blockvote::Block::default().digest(),
            tip_best: goldfish_blockvote::Block::default().digest(),
            stats: HashMap::new(),
        }
    }

    fn broadcast(msg: &goldfish_message::Message, inboxes: &mut Vec<network::SimulationInbox>) {
        log::debug!("Broadcasting: {:?}", msg);

        for inbox in inboxes {
            inbox.make_available(msg);
        }
    }

    #[allow(dead_code)]
    pub fn stats(&self) -> HashMap<usize, ValidatorLedgerStats> {
        self.stats.clone()
    }

    pub fn update_stats(&mut self, r: usize) {
        let stats = ValidatorLedgerStats {
            ledger_best: LedgerStats {
                length: self.bvtree.get_block_height(&self.tip_best),
                age: self.bvtree.get_block(self.tip_best.clone()).unwrap().slot(),
            },
            ledger_fast: LedgerStats {
                length: self.bvtree.get_block_height(&self.tip_fast),
                age: self.bvtree.get_block(self.tip_fast.clone()).unwrap().slot(),
            },
            ledger_slow: LedgerStats {
                length: self.bvtree.get_block_height(&self.tip_slow),
                age: self.bvtree.get_block(self.tip_slow.clone()).unwrap().slot(),
            },
        };
        self.stats.insert(r, stats);
    }

    #[allow(dead_code)]
    pub fn dump_dotfile(&self) -> String {
        self.bvtree.dump_dotfile()
    }
}

impl HonestValidator for Validator {
    fn step(
        &mut self,
        lotteries: &goldfish_type::Lotteries,
        r: usize,
        inboxes: &mut Vec<network::SimulationInbox>,
        my_inbox: usize,
    ) {
        let t = (r / 4) as goldfish_type::Slot;
        let myid = self.id;

        // log::info!("r={} id={} STEP", r, myid);

        self.limbo.extend(inboxes[my_inbox].collect_inbox());
        log::info!("r={} id={} LIMBO {}", r, myid, self.limbo.len());

        // drop messages we have processed before
        self.limbo
            .retain(|msg| !self.msgs_relayed.contains(&msg.digest()));

        // drop votes that have expired and won't be needed anyway
        self.limbo.retain(|msg| {
            if let goldfish_message::Message::Piece(goldfish_message::Piece::Vote(_)) = msg {
                !(t > 0 && msg.slot() < t - 1)
            } else {
                true
            }
        });

        let mut bvset_validation_rw_cache = HashMap::new();
        let mut bvset_validation_cache = goldfish_type::UnionValidationCache::new(
            &self.validation_cache,
            &mut bvset_validation_rw_cache,
        );

        let mut done = false;
        while !done {
            done = true;

            self.limbo.make_contiguous().sort_by_key(|m| {
                (
                    match m {
                        goldfish_message::Message::Piece(goldfish_message::Piece::Block(_)) => 0,
                        goldfish_message::Message::Piece(goldfish_message::Piece::Vote(_)) => 1,
                        goldfish_message::Message::Proposal(_) => 2,
                    },
                    m.slot(),
                )
            });

            for _ in 0..self.limbo.len() {
                let msg = self.limbo.pop_front().unwrap();

                if msg.slot() > t {
                    self.limbo.push_back(msg);
                    continue;
                }

                let msg_is_valid = msg.is_valid(
                    lotteries,
                    &mut goldfish_type::RoValidationCache::new(&bvset_validation_cache),
                    &self.pki,
                    &goldfish_blockvote::BufferAugmentedBvTree::new(
                        &self.bvtree,
                        &self.buffer_blocks,
                        &self.buffer_votes,
                    ),
                );

                match msg_is_valid {
                    goldfish_type::ValidationResult::Valid => {
                        log::trace!("r={} id={} VALID msg from limbo: {:?}", r, myid, msg);
                        match msg.clone() {
                            goldfish_message::Message::Proposal(p) => {
                                self.buffer_proposals.push(p.clone());
                            }
                            goldfish_message::Message::Piece(x) => match x {
                                goldfish_message::Piece::Vote(v) => {
                                    self.buffer_votes.insert(v.digest(), v.clone());
                                }
                                goldfish_message::Piece::Block(b) => {
                                    self.buffer_blocks.insert(b.digest(), b.clone());
                                }
                            },
                        }

                        // Self::broadcast(msg, inboxes); // TODO TODO TODO: disabled relaying for simulation experiments
                        self.msgs_relayed.insert(msg.digest());

                        done = false;
                        assert!(
                            msg.is_valid(
                                lotteries,
                                &mut bvset_validation_cache,
                                &self.pki,
                                &goldfish_blockvote::BufferAugmentedBvTree::new(
                                    &self.bvtree,
                                    &self.buffer_blocks,
                                    &self.buffer_votes,
                                )
                            ) == goldfish_type::ValidationResult::Valid
                        );
                    }
                    goldfish_type::ValidationResult::Invalid => {
                        log::warn!("r={} id={} INVALID msg from limbo: {:?}", r, myid, msg);
                    }
                    goldfish_type::ValidationResult::Unknown => {
                        log::debug!("r={} id={} UNKNOWN msg from limbo: {:?}", r, myid, msg);
                        self.limbo.push_back(msg);
                        continue;
                    }
                }
            }
        }

        match r % 4 {
            0 => {
                log::info!("r={} id={} PROPOSE", r, myid);

                let rho = lotteries.block.open(&self.sk_vrf, t);
                if lotteries
                    .block
                    .is_winning(&self.pki.get(&self.id).unwrap().1, t, &rho)
                {
                    log::info!("r={} id={} Proposing ...", r, myid);

                    let mut bvtree_new = self.bvtree.clone();
                    bvtree_new.merge(
                        lotteries,
                        &mut goldfish_type::RoValidationCache::new(&self.validation_cache),
                        &self.pki,
                        &mut self.buffer_blocks.clone(),
                        &mut self.buffer_votes.clone(),
                        None,
                    );
                    bvtree_new.expire_votes_before((t as isize) - 1);
                    let h_tip = bvtree_new.ghost_eph((t as isize) - 1, 0);
                    let b_new = goldfish_blockvote::Block::create(
                        &self.sk_sig,
                        (self.id, t),
                        rho,
                        h_tip,
                        format!("t={} id={}", t, self.id),
                    );
                    let p_new = goldfish_message::Proposal::create(
                        &self.sk_sig,
                        &bvtree_new,
                        b_new.clone(),
                    );

                    // debug & pre-heat signature validation cache (for simulation)
                    assert!(
                        p_new.is_valid(
                            lotteries,
                            &mut goldfish_type::RoValidationCache::new(&self.validation_cache),
                            &self.pki,
                            &bvtree_new
                        ) == goldfish_type::ValidationResult::Valid
                    );
                    Self::broadcast(&goldfish_message::Message::Proposal(p_new), inboxes);
                }
            }

            1 => {
                log::info!("r={} id={} VOTE", r, myid);

                if let Some(p) = self
                    .buffer_proposals
                    .iter()
                    .filter(|p| p.slot() == t)
                    .min_by_key(|p| p.prio())
                {
                    log::info!("r={} id={} Merging: {:?}", r, myid, p);

                    self.bvtree.merge(
                        lotteries,
                        &mut self.validation_cache,
                        &self.pki,
                        &mut self.buffer_blocks,
                        &mut self.buffer_votes,
                        Some(p),
                    );

                    Self::broadcast(
                        &goldfish_message::Message::Piece(goldfish_message::Piece::Block(p.b())),
                        inboxes,
                    );
                }

                let rho = lotteries.vote.open(&self.sk_vrf, t);
                if lotteries
                    .vote
                    .is_winning(&self.pki.get(&self.id).unwrap().1, t, &rho)
                {
                    log::info!("r={} id={} Voting ...", r, myid);

                    self.bvtree.expire_votes_before((t as isize) - 1);
                    let h_tip = self.bvtree.ghost_eph((t as isize) - 1, 0);
                    let v_new =
                        goldfish_blockvote::Vote::create(&self.sk_sig, (self.id, t), rho, h_tip);
                    let x_new = goldfish_message::Piece::Vote(v_new);

                    // debug & pre-heat signature validation cache (for simulation)
                    assert!(
                        x_new.is_valid(
                            lotteries,
                            &mut self.validation_cache,
                            &self.pki,
                            &self.bvtree
                        ) == goldfish_type::ValidationResult::Valid
                    );
                    Self::broadcast(&goldfish_message::Message::Piece(x_new), inboxes);
                }
            }

            2 => {
                log::info!("r={} id={} FAST-CONFIRM", r, myid);

                // clean up unneeded votes/proposals -> performance (esp. after sleeping)
                self.buffer_proposals.retain(|p| p.slot() >= t);
                self.buffer_votes.retain(|_, v| v.slot() >= t);

                log::debug!("r={} id={} FAST-CONFIRM-Merge", r, myid);

                self.bvtree.merge(
                    lotteries,
                    &mut self.validation_cache,
                    &self.pki,
                    &mut self.buffer_blocks,
                    &mut self.buffer_votes,
                    None,
                );
                self.bvtree.expire_votes_before(t as isize);
                let h_tip = self.bvtree.ghost_eph(
                    t as isize,
                    ((self.pki.len() as f64)
                        * (0.75 + 0.5 * self.confirm_fast_eps)
                        * lotteries.vote.success_probability())
                    .ceil() as usize,
                );

                if self.bvtree.get_block_height(&h_tip)
                    > self.bvtree.get_block_height(&self.tip_fast)
                {
                    self.tip_fast = h_tip;
                }
            }

            3 => {
                log::info!("r={} id={} SLOW-CONFIRM", r, myid);

                // clean up unneeded votes/proposals -> performance (esp. after sleeping)
                self.buffer_proposals.retain(|p| p.slot() >= t);
                self.buffer_votes.retain(|_, v| v.slot() >= t);

                log::debug!("r={} id={} SLOW-CONFIRM-Merge", r, myid);

                self.bvtree.merge(
                    lotteries,
                    &mut self.validation_cache,
                    &self.pki,
                    &mut self.buffer_blocks,
                    &mut self.buffer_votes,
                    None,
                );
                self.bvtree.expire_votes_before(t as isize);
                let h_tip = self.bvtree.ghost_eph(t as isize, 0);
                let h_tip = self.bvtree.truncate_back_to_slot(
                    &h_tip,
                    (t as isize) - (self.confirm_slow_kappa as isize),
                );
                self.tip_slow = h_tip;
            }

            _ => unreachable!(),
        }

        log::info!("r={} id={} CLEANUP", r, myid);

        if self.bvtree.get_block_height(&self.tip_fast)
            > self.bvtree.get_block_height(&self.tip_slow)
        {
            self.tip_best = self.tip_fast.clone();
        } else {
            self.tip_best = self.tip_slow.clone();
        }

        self.buffer_proposals.retain(|p| p.slot() >= t);
        self.buffer_votes.retain(|_, v| v.slot() >= t - 1);
        self.buffer_blocks.retain(|_, v| v.slot() >= t - 1);
        self.limbo
            .retain(|m| (m.slot() as isize) >= (t as isize) - (self.confirm_slow_kappa as isize));

        self.update_stats(r);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum DaValidatorSleepStatus {
    Asleep,
    Dreamy,
    Awake,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[allow(dead_code)]
pub enum DaScheduleStatus {
    Asleep,
    Awake,
}

#[derive(Debug)]
pub struct DaSimulationValidator {
    validator: Validator,
    da_schedule: Vec<DaScheduleStatus>,
    sleep_status: DaValidatorSleepStatus,
    r_end_of_joining: usize,
    stats: HashMap<usize, ValidatorDaStats>,
}

impl DaSimulationValidator {
    pub fn new(validator: Validator, da_schedule: Vec<DaScheduleStatus>) -> Self {
        Self {
            validator,
            da_schedule,
            sleep_status: DaValidatorSleepStatus::Awake,
            r_end_of_joining: 0,
            stats: HashMap::new(),
        }
    }

    #[allow(dead_code)]
    pub fn stats(&self) -> HashMap<usize, (ValidatorDaStats, ValidatorLedgerStats)> {
        let keys: Vec<usize> = self.stats.keys().cloned().collect();
        let stats1 = self.validator.stats();
        let stats2 = self.stats.clone();
        HashMap::from_iter(keys.iter().map(|r| (*r, (stats2[r], stats1[r]))))
    }

    #[allow(dead_code)]
    pub fn dump_dotfile(&self) -> String {
        self.validator.dump_dotfile()
    }
}

impl HonestValidator for DaSimulationValidator {
    fn step(
        &mut self,
        lotteries: &goldfish_type::Lotteries,
        r: usize,
        inboxes: &mut Vec<network::SimulationInbox>,
        my_inbox: usize,
    ) {
        let myid = self.validator.id;

        // https://stackoverflow.com/a/49908888
        (|| match self.da_schedule[r as usize] {
            DaScheduleStatus::Asleep => {
                log::info!("r={} id={} ASLEEP", r, myid);
                self.sleep_status = DaValidatorSleepStatus::Asleep;
                self.validator.update_stats(r);
                return;
            }

            DaScheduleStatus::Awake => {
                if self.sleep_status == DaValidatorSleepStatus::Asleep {
                    self.sleep_status = DaValidatorSleepStatus::Dreamy;
                    let t = (r / 4) as goldfish_type::Slot;
                    self.r_end_of_joining = t as usize * 4 + 3;
                }

                if self.sleep_status == DaValidatorSleepStatus::Dreamy {
                    if r == self.r_end_of_joining {
                        self.sleep_status = DaValidatorSleepStatus::Awake;
                    } else {
                        log::info!("r={} id={} DREAMY", r, myid);
                        // TODO TODO TODO: relaying (disabled for simulation experiments)
                        self.validator.update_stats(r);
                        return;
                    }
                }

                assert!(self.sleep_status == DaValidatorSleepStatus::Awake);
                log::info!("r={} id={} AWAKE", r, myid);

                self.validator.step(lotteries, r, inboxes, my_inbox);
            }
        })();

        let stats = ValidatorDaStats {
            status: self.sleep_status,
        };
        self.stats.insert(r, stats);
    }
}
