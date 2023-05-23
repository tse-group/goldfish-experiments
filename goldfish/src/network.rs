use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use crate::goldfish_message;
use crate::goldfish_type;

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct CommunicationStats {
    pub all_size: usize,
    pub all_count: usize,
    pub proposal_size: usize,
    pub proposal_count: usize,
    pub piece_block_size: usize,
    pub piece_block_count: usize,
    pub piece_vote_size: usize,
    pub piece_vote_count: usize,
}

#[derive(Debug, Clone)]
pub struct SimulationInbox {
    msgs: Arc<Mutex<Vec<goldfish_message::Message>>>,
    msgs_inflight: Arc<Mutex<Vec<goldfish_message::Message>>>,
    msgs_seen: Arc<Mutex<HashSet<goldfish_type::Hash>>>,
    stats: Arc<Mutex<HashMap<usize, CommunicationStats>>>,
}

impl SimulationInbox {
    pub fn new() -> Self {
        Self {
            msgs: Arc::new(Mutex::new(Vec::new())),
            msgs_inflight: Arc::new(Mutex::new(Vec::new())),
            msgs_seen: Arc::new(Mutex::new(HashSet::new())),
            stats: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn make_available(&mut self, msg: &goldfish_message::Message) {
        let hash = msg.digest();
        let mut self_msgs_seen = self.msgs_seen.lock().unwrap();
        let mut self_msgs_inflight = self.msgs_inflight.lock().unwrap();
        if !self_msgs_seen.contains(&hash) {
            self_msgs_inflight.push(msg.clone());
            self_msgs_seen.insert(hash);
        }
    }

    #[allow(dead_code)]
    pub fn adversary_peek(
        &mut self,
    ) -> (
        Vec<goldfish_message::Message>,
        Vec<goldfish_message::Message>,
    ) {
        let self_msgs = self.msgs.lock().unwrap();
        let self_msgs_inflight = self.msgs_inflight.lock().unwrap();
        (self_msgs.clone(), self_msgs_inflight.clone())
    }

    pub fn collect_inbox(&mut self) -> Vec<goldfish_message::Message> {
        let mut self_msgs = self.msgs.lock().unwrap();
        self_msgs.drain(..).collect()
    }

    pub fn deliver_msgs_inflight(&mut self, r: usize) {
        let mut self_msgs = self.msgs.lock().unwrap();
        let mut self_msgs_inflight = self.msgs_inflight.lock().unwrap();
        let mut self_stats = self.stats.lock().unwrap();

        let self_msgs_inflight_all = self_msgs_inflight.iter();
        let self_msgs_inflight_proposal = self_msgs_inflight.iter().filter(|m| {
            if let goldfish_message::Message::Proposal(_) = m {
                true
            } else {
                false
            }
        });
        let self_msgs_inflight_piece_block = self_msgs_inflight.iter().filter(|m| {
            if let goldfish_message::Message::Piece(goldfish_message::Piece::Block(_)) = m {
                true
            } else {
                false
            }
        });
        let self_msgs_inflight_piece_vote = self_msgs_inflight.iter().filter(|m| {
            if let goldfish_message::Message::Piece(goldfish_message::Piece::Vote(_)) = m {
                true
            } else {
                false
            }
        });
        let stats = CommunicationStats {
            all_count: self_msgs_inflight_all.clone().count(),
            all_size: self_msgs_inflight_all.clone().map(|m| m.size()).sum(),
            proposal_count: self_msgs_inflight_proposal.clone().count(),
            proposal_size: self_msgs_inflight_proposal.clone().map(|m| m.size()).sum(),
            piece_block_count: self_msgs_inflight_piece_block.clone().count(),
            piece_block_size: self_msgs_inflight_piece_block
                .clone()
                .map(|m| m.size())
                .sum(),
            piece_vote_count: self_msgs_inflight_piece_vote.clone().count(),
            piece_vote_size: self_msgs_inflight_piece_vote
                .clone()
                .map(|m| m.size())
                .sum(),
        };

        self_stats.insert(r, stats);
        self_msgs.append(&mut self_msgs_inflight);
    }

    #[allow(dead_code)]
    pub fn stats(&self) -> HashMap<usize, CommunicationStats> {
        let self_stats = self.stats.lock().unwrap();
        self_stats.clone()
    }
}
