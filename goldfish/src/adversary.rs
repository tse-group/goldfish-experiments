use crate::goldfish_type;
use crate::goldfish_validator;
use crate::network;

pub trait Adversary<V: goldfish_validator::HonestValidator> {
    fn new() -> Self;
    fn corrupt(&mut self, validator: V);
    fn step(
        &mut self,
        lotteries: &goldfish_type::Lotteries,
        r: usize,
        inboxes: &mut Vec<network::SimulationInbox>,
        my_inbox: usize,
    );
}

pub struct CrashFaults<V: goldfish_validator::HonestValidator> {
    validators: Vec<V>,
}

impl<V: goldfish_validator::HonestValidator> Adversary<V> for CrashFaults<V> {
    fn new() -> Self {
        Self {
            validators: Vec::new(),
        }
    }

    fn corrupt(&mut self, validator: V) {
        self.validators.push(validator);
    }

    fn step(
        &mut self,
        _lotteries: &goldfish_type::Lotteries,
        _r: usize,
        inboxes: &mut Vec<network::SimulationInbox>,
        my_inbox: usize,
    ) {
        // crash faults
        inboxes[my_inbox].collect_inbox();
    }
}
