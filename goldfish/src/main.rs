#![feature(hash_drain_filter)]

use clap::{Parser, Subcommand};
use goldfish_validator::DaScheduleStatus;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_with::with_prefix;
use std::collections::HashMap;
use std::thread;

mod adversary;
mod ghash;
mod goldfish_blockvote;
mod goldfish_message;
mod goldfish_type;
mod goldfish_validator;
mod lottery;
mod network;
mod sig;
mod vrf;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Turn debugging information on
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Simulate the protocol
    Simulate {
        /// Duration of simulation (number of slots)
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..), default_value_t=1)]
        t_horizon: u64,

        /// Number of parties
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..), default_value_t=5)]
        n: u64,

        /// Number of adversary parties
        #[arg(long, default_value_t = 0)]
        f: u64,

        /// Slow confirmation kappa
        #[arg(long, default_value_t = 10)]
        confirm_slow_kappa: u64,

        /// Fast confirmation epsilon
        #[arg(long, default_value_t = 0.001)]
        confirm_fast_eps: f64,

        /// Block lottery success probability
        #[arg(long, default_value_t = 1.0)]
        probability_lottery_block: f64,

        /// Vote lottery success probability
        #[arg(long, default_value_t = 1.0)]
        probability_lottery_vote: f64,

        #[command(subcommand)]
        command: SimulationCommands,
    },
}

#[derive(Subcommand)]
enum SimulationCommands {
    /// Full participation
    FullParticipation {},

    /// Alternate periods of full/reduced participation
    SimpleAlternatingParticipation {
        /// Fraction of horizon for warm-up
        #[arg(long, default_value_t = 0.2)]
        fraction_warmup: f64,

        /// Fraction of period for low participation
        #[arg(long, default_value_t = 0.5)]
        fraction_low_participation: f64,

        /// Number of periods
        #[arg(long, value_parser = clap::value_parser!(u64).range(1..), default_value_t = 1)]
        periods: u64,

        /// Level of low participation
        #[arg(long, default_value_t = 0.5)]
        low_participation: f64,
    },

    /// Participation schedule inspired by Momose & Ren "Constant Latency in Sleepy Consensus" (CCS'22)
    MomoseRenParticipation {
        /// Fraction of horizon for warm-up
        #[arg(long, default_value_t = 0.2)]
        fraction_warmup: f64,

        /// Fraction of parties to change per slot
        #[arg(long, default_value_t = 0.01)]
        fraction_crement: f64,

        /// Lower-bound on awake parties at low participation
        #[arg(long)]
        fraction_low_participation_lb: f64,

        /// Upper-bound on awake parties at low participation
        #[arg(long)]
        fraction_low_participation_ub: f64,

        /// Lower-bound on awake parties at high participation
        #[arg(long)]
        fraction_high_participation_lb: f64,

        /// Upper-bound on awake parties at high participation
        #[arg(long)]
        fraction_high_participation_ub: f64,
    },

    /// Sample participation level iid uniform in [1,N] per slot
    IidParticipation {
        /// Fraction of horizon for iid
        #[arg(long, default_value_t = 0.6)]
        fraction_iid: f64,

        /// Lower-bound on awake parties
        #[arg(long)]
        fraction_participation_lb: f64,
    },
}

use crate::adversary::Adversary as _;
use crate::goldfish_validator::HonestValidator as _;
use crate::sig::Scheme as _;
use crate::vrf::Scheme as _;

fn _instantiate_validators_with_da_schedules(
    pki: &goldfish_type::Pki,
    mut sks: Vec<(
        <goldfish_type::Sigs as sig::Scheme>::Sk,
        <goldfish_type::Vrfs as vrf::Scheme>::Sk,
    )>,
    _sim_horizon: std::ops::Range<usize>,
    confirm_slow_kappa: usize,
    confirm_fast_eps: f64,
    da_schedules: Vec<Vec<DaScheduleStatus>>,
) -> (
    Vec<goldfish_validator::DaSimulationValidator>,
    Vec<Vec<goldfish_validator::DaScheduleStatus>>,
) {
    let mut validators = Vec::new();
    for id in 0..(pki.len() as u64) {
        let (sk_sig, sk_vrf) = sks.remove(0);
        validators.push(goldfish_validator::DaSimulationValidator::new(
            goldfish_validator::Validator::new(
                id,
                sk_sig,
                sk_vrf,
                pki.clone(),
                confirm_slow_kappa,
                confirm_fast_eps,
            ),
            da_schedules[id as usize].clone(),
        ));
    }
    (validators, da_schedules)
}

fn instantiate_validators_with_da_schedule_fn<
    F: Fn(goldfish_type::Id, usize) -> goldfish_validator::DaScheduleStatus,
>(
    pki: &goldfish_type::Pki,
    sks: Vec<(
        <goldfish_type::Sigs as sig::Scheme>::Sk,
        <goldfish_type::Vrfs as vrf::Scheme>::Sk,
    )>,
    sim_horizon: std::ops::Range<usize>,
    confirm_slow_kappa: usize,
    confirm_fast_eps: f64,
    da_schedule_fn: F,
) -> (
    Vec<goldfish_validator::DaSimulationValidator>,
    Vec<Vec<goldfish_validator::DaScheduleStatus>>,
) {
    let mut da_schedules = Vec::new();
    for id in 0..(pki.len() as u64) {
        let mut da_schedule = [goldfish_validator::DaScheduleStatus::Awake; 4].to_vec();
        for r in sim_horizon.clone() {
            da_schedule.push(da_schedule_fn(id, r));
        }
        da_schedules.push(da_schedule.clone());
    }

    _instantiate_validators_with_da_schedules(
        pki,
        sks,
        sim_horizon,
        confirm_slow_kappa,
        confirm_fast_eps,
        da_schedules,
    )
}

fn instantiate_validators_always_awake(
    pki: &goldfish_type::Pki,
    sks: Vec<(
        <goldfish_type::Sigs as sig::Scheme>::Sk,
        <goldfish_type::Vrfs as vrf::Scheme>::Sk,
    )>,
    sim_horizon: std::ops::Range<usize>,
    confirm_slow_kappa: usize,
    confirm_fast_eps: f64,
) -> (
    Vec<goldfish_validator::DaSimulationValidator>,
    Vec<Vec<goldfish_validator::DaScheduleStatus>>,
) {
    instantiate_validators_with_da_schedule_fn(
        pki,
        sks,
        sim_horizon,
        confirm_slow_kappa,
        confirm_fast_eps,
        |_id, _r| goldfish_validator::DaScheduleStatus::Awake,
    )
}

fn instantiate_validators_intermittent_fraction_asleep_01(
    pki: &goldfish_type::Pki,
    sks: Vec<(
        <goldfish_type::Sigs as sig::Scheme>::Sk,
        <goldfish_type::Vrfs as vrf::Scheme>::Sk,
    )>,
    sim_horizon: std::ops::Range<usize>,
    confirm_slow_kappa: usize,
    confirm_fast_eps: f64,
    fraction_warmup: f64,
    fraction_low_participation: f64,
    periods: usize,
    low_participation: f64,
) -> (
    Vec<goldfish_validator::DaSimulationValidator>,
    Vec<Vec<goldfish_validator::DaScheduleStatus>>,
) {
    let mut non_sleepy: Vec<usize> = (0..pki.len()).collect();
    non_sleepy.shuffle(&mut thread_rng());
    non_sleepy = non_sleepy[..(low_participation * pki.len() as f64).ceil() as usize].to_vec();

    let mut sleep_pattern = [goldfish_validator::DaScheduleStatus::Awake; 4].to_vec();
    for r in sim_horizon.clone() {
        let progression = (r - 4) as f64 / (sim_horizon.end as f64);
        if progression < fraction_warmup {
            sleep_pattern.push(goldfish_validator::DaScheduleStatus::Awake);
        } else {
            let progression = (progression - fraction_warmup) / (1.0 - fraction_warmup);
            let period = (progression * (periods as f64)).floor() as usize;
            let progression = (progression - (period as f64) / (periods as f64)) * (periods as f64);
            if progression < fraction_low_participation {
                sleep_pattern.push(goldfish_validator::DaScheduleStatus::Asleep);
            } else {
                sleep_pattern.push(goldfish_validator::DaScheduleStatus::Awake);
            }
        }
    }

    instantiate_validators_with_da_schedule_fn(
        pki,
        sks,
        sim_horizon,
        confirm_slow_kappa,
        confirm_fast_eps,
        |id, r| {
            if non_sleepy.iter().find(|&&i| i == id as usize).is_some() {
                goldfish_validator::DaScheduleStatus::Awake
            } else {
                sleep_pattern[r]
            }
        },
    )
}

fn instantiate_validators_with_awake_count_schedule_fn<F: Fn(usize) -> usize>(
    pki: &goldfish_type::Pki,
    sks: Vec<(
        <goldfish_type::Sigs as sig::Scheme>::Sk,
        <goldfish_type::Vrfs as vrf::Scheme>::Sk,
    )>,
    sim_horizon: std::ops::Range<usize>,
    confirm_slow_kappa: usize,
    confirm_fast_eps: f64,
    awake_count_schedule_fn: F,
) -> (
    Vec<goldfish_validator::DaSimulationValidator>,
    Vec<Vec<goldfish_validator::DaScheduleStatus>>,
) {
    let n = pki.len();

    let mut da_schedules = Vec::new();
    for _ in 0..(n as u64) {
        let da_schedule = [goldfish_validator::DaScheduleStatus::Awake; 4].to_vec();
        da_schedules.push(da_schedule.clone());
    }

    let mut parties_awake: Vec<u64> = (0..((n as u64) - 1)).collect();
    let mut parties_asleep = Vec::new();

    for r in sim_horizon.clone() {
        let mut target_count = awake_count_schedule_fn(r);
        if target_count == 0 {
            target_count = 0;
        } else {
            target_count = target_count - 1;
        }

        if parties_awake.len() < target_count {
            // put some parties to sleep
            let parties_to_move = target_count - parties_awake.len();
            parties_asleep.shuffle(&mut thread_rng());
            for _ in 0..parties_to_move {
                let party = parties_asleep.pop().unwrap();
                parties_awake.push(party);
            }
        } else if parties_awake.len() > target_count {
            // wake some parties up
            let parties_to_move = parties_awake.len() - target_count;
            parties_awake.shuffle(&mut thread_rng());
            for _ in 0..parties_to_move {
                let party = parties_awake.pop().unwrap();
                parties_asleep.push(party);
            }
        } else {
            // no change
        }

        for id in 0..(pki.len() as u64) {
            if id == (n as u64) - 1 {
                da_schedules[id as usize].push(goldfish_validator::DaScheduleStatus::Awake);
                continue;
            }

            if parties_awake.contains(&id) {
                da_schedules[id as usize].push(goldfish_validator::DaScheduleStatus::Awake);
            } else {
                da_schedules[id as usize].push(goldfish_validator::DaScheduleStatus::Asleep);
            }
        }
    }

    _instantiate_validators_with_da_schedules(
        pki,
        sks,
        sim_horizon,
        confirm_slow_kappa,
        confirm_fast_eps,
        da_schedules,
    )
}

fn instantiate_validators_iid01(
    pki: &goldfish_type::Pki,
    sks: Vec<(
        <goldfish_type::Sigs as sig::Scheme>::Sk,
        <goldfish_type::Vrfs as vrf::Scheme>::Sk,
    )>,
    sim_horizon: std::ops::Range<usize>,
    confirm_slow_kappa: usize,
    confirm_fast_eps: f64,
    fraction_iid: f64,
    fraction_participation_lb: f64,
) -> (
    Vec<goldfish_validator::DaSimulationValidator>,
    Vec<Vec<goldfish_validator::DaScheduleStatus>>,
) {
    let n = pki.len();
    let n0 = (n as f64 * fraction_participation_lb).ceil() as usize;

    instantiate_validators_with_awake_count_schedule_fn(
        pki,
        sks,
        sim_horizon.clone(),
        confirm_slow_kappa,
        confirm_fast_eps,
        |r| {
            let progression = (r - 4) as f64 / (sim_horizon.end as f64 - 4.0);
            if progression < (1.0 - fraction_iid) / 2.0
                || progression > 1.0 - (1.0 - fraction_iid) / 2.0
            {
                n
            } else {
                rand::random::<usize>() % (n - n0) + n0
            }
        },
    )
}

fn instantiate_validators_momoseren(
    pki: &goldfish_type::Pki,
    sks: Vec<(
        <goldfish_type::Sigs as sig::Scheme>::Sk,
        <goldfish_type::Vrfs as vrf::Scheme>::Sk,
    )>,
    sim_horizon: std::ops::Range<usize>,
    confirm_slow_kappa: usize,
    confirm_fast_eps: f64,
    fraction_warmup: f64,
    fraction_crement: f64,
    fraction_low_participation_lb: f64,
    fraction_low_participation_ub: f64,
    fraction_high_participation_lb: f64,
    fraction_high_participation_ub: f64,
) -> (
    Vec<goldfish_validator::DaSimulationValidator>,
    Vec<Vec<goldfish_validator::DaScheduleStatus>>,
) {
    let n = pki.len();
    let mut awake_count_schedule = [1.0; 4].to_vec();
    let mut state: usize = 0;

    fn truncate(x: f64, lb: f64, ub: f64) -> f64 {
        if x < lb {
            lb
        } else if x > ub {
            ub
        } else {
            x
        }
    }

    let rand_crement = || match rand::random::<bool>() {
        true => fraction_crement,
        false => -fraction_crement,
    };

    for r in sim_horizon.clone() {
        let progression = (r - 4) as f64 / (sim_horizon.end as f64 - 4.0);
        if progression < fraction_warmup || progression > 1.0 - fraction_warmup {
            awake_count_schedule.push(1.0);
        } else {
            let progression = (progression - fraction_warmup) / (1.0 - 2.0 * fraction_warmup);
            if progression < 0.25 {
                if state == 0 {
                    awake_count_schedule.push(
                        (fraction_low_participation_lb + fraction_high_participation_ub) / 2.0,
                    );
                    state = 1;
                } else {
                    let newval = awake_count_schedule.last().unwrap() + rand_crement();
                    let newval = truncate(
                        newval,
                        fraction_low_participation_lb,
                        fraction_high_participation_ub,
                    );
                    awake_count_schedule.push(newval);
                }
            } else if progression < 0.5 {
                let newval = rand::random::<usize>()
                    % ((n as f64 * (fraction_high_participation_ub - fraction_low_participation_lb))
                        .round() as usize)
                    + ((n as f64 * fraction_low_participation_lb) as usize);
                awake_count_schedule.push(newval as f64 / (n as f64));
            } else if progression < 0.75 {
                if state == 1 {
                    awake_count_schedule.push(
                        (fraction_high_participation_lb + fraction_high_participation_ub) / 2.0,
                    );
                    state = 2;
                } else {
                    let newval = awake_count_schedule.last().unwrap() + rand_crement();
                    let newval = truncate(
                        newval,
                        fraction_high_participation_lb,
                        fraction_high_participation_ub,
                    );
                    awake_count_schedule.push(newval);
                }
            } else {
                if state == 2 {
                    awake_count_schedule.push(
                        (fraction_low_participation_lb + fraction_low_participation_ub) / 2.0,
                    );
                    state = 3;
                } else {
                    let newval = awake_count_schedule.last().unwrap() + rand_crement();
                    let newval = truncate(
                        newval,
                        fraction_low_participation_lb,
                        fraction_low_participation_ub,
                    );
                    awake_count_schedule.push(newval);
                }
            }
        }
    }

    let awake_count_schedule = awake_count_schedule
        .iter()
        .map(|x| (x * (n as f64)).round() as usize)
        .collect::<Vec<_>>();

    instantiate_validators_with_awake_count_schedule_fn(
        pki,
        sks,
        sim_horizon.clone(),
        confirm_slow_kappa,
        confirm_fast_eps,
        |r| awake_count_schedule[r],
    )
}

fn probability_f64_to_u64(probability: f64) -> u64 {
    if probability > 0.999999 {
        0xffffffffffffffffu64
    } else if probability < 0.000001 {
        0x0000000000000000u64
    } else {
        (0xffffffffffffffffu64 as f64 * probability) as u64
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    env_logger::Builder::from_default_env()
        .filter_level(match cli.verbose {
            0 => log::LevelFilter::Error,
            1 => log::LevelFilter::Warn,
            2 => log::LevelFilter::Info,
            3 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
        .format_module_path(true)
        // .format_target(true)
        .format_timestamp_millis()
        .init();

    log::error!("ERROR");
    log::warn!("WARN");
    log::info!("INFO");
    log::debug!("DEBUG");
    log::trace!("TRACE");

    match cli.command {
        Commands::Simulate {
            t_horizon: param_t_horizon,
            n: param_n,
            f: param_f,
            confirm_slow_kappa: param_confirm_slow_kappa,
            confirm_fast_eps: param_confirm_fast_eps,
            probability_lottery_block: param_probability_lottery_block,
            probability_lottery_vote: param_probability_lottery_vote,
            command: param_scenario,
        } => {
            let param_r_horizon = 4 * param_t_horizon as usize;
            let param_sim_horizon = 4..(4 + param_r_horizon);
            let param_confirm_slow_kappa = param_confirm_slow_kappa as usize;

            // SETUP

            let mut sigs = goldfish_type::Sigs::new();
            let mut vrfs = goldfish_type::Vrfs::new();
            let mut pki = goldfish_type::Pki::new();
            let mut tmp_sks = Vec::new();
            for id in 0..param_n {
                let (sk_sig, pk_sig) = sigs.gen();
                let (sk_vrf, pk_vrf) = vrfs.gen();
                pki.insert(id, (pk_sig, pk_vrf));
                tmp_sks.push((sk_sig, sk_vrf));
            }

            let lottery_block: goldfish_type::Lottery = goldfish_type::Lottery::new(
                "block".as_bytes(),
                probability_f64_to_u64(param_probability_lottery_block),
            );
            let lottery_vote: goldfish_type::Lottery = goldfish_type::Lottery::new(
                "vote".as_bytes(),
                probability_f64_to_u64(param_probability_lottery_vote),
            );
            let lotteries = goldfish_type::Lotteries::new(lottery_block, lottery_vote);

            let (mut validators, mut da_schedules) = match param_scenario {
                SimulationCommands::FullParticipation {} => instantiate_validators_always_awake(
                    &pki,
                    tmp_sks,
                    param_sim_horizon.clone(),
                    param_confirm_slow_kappa,
                    param_confirm_fast_eps,
                ),

                SimulationCommands::SimpleAlternatingParticipation {
                    fraction_warmup: param_fraction_warmup,
                    fraction_low_participation: param_fraction_low_participation,
                    periods: param_periods,
                    low_participation: param_low_participation,
                } => instantiate_validators_intermittent_fraction_asleep_01(
                    &pki,
                    tmp_sks,
                    param_sim_horizon.clone(),
                    param_confirm_slow_kappa,
                    param_confirm_fast_eps,
                    param_fraction_warmup,
                    param_fraction_low_participation,
                    param_periods as usize,
                    param_low_participation,
                ),

                SimulationCommands::MomoseRenParticipation {
                    fraction_warmup: param_fraction_warmup,
                    fraction_crement: param_fraction_crement,
                    fraction_low_participation_lb: param_fraction_low_participation_lb,
                    fraction_low_participation_ub: param_fraction_low_participation_ub,
                    fraction_high_participation_lb: param_fraction_high_participation_lb,
                    fraction_high_participation_ub: param_fraction_high_participation_ub,
                } => instantiate_validators_momoseren(
                    &pki,
                    tmp_sks,
                    param_sim_horizon.clone(),
                    param_confirm_slow_kappa,
                    param_confirm_fast_eps,
                    param_fraction_warmup,
                    param_fraction_crement,
                    param_fraction_low_participation_lb,
                    param_fraction_low_participation_ub,
                    param_fraction_high_participation_lb,
                    param_fraction_high_participation_ub,
                ),

                SimulationCommands::IidParticipation {
                    fraction_iid: param_fraction_iid,
                    fraction_participation_lb: param_fraction_participation_lb,
                } => instantiate_validators_iid01(
                    &pki,
                    tmp_sks,
                    param_sim_horizon.clone(),
                    param_confirm_slow_kappa,
                    param_confirm_fast_eps,
                    param_fraction_iid,
                    param_fraction_participation_lb,
                ),
            };

            // CORRUPTION

            type Adversary = adversary::CrashFaults<goldfish_validator::DaSimulationValidator>;
            let mut adversary = Adversary::new();
            for _id in 0..param_f {
                adversary.corrupt(validators.remove(0));
                da_schedules.remove(0);
            }

            // MAIN LOOP
            log::info!("Main loop");

            let mut inboxes = Vec::new();
            for _id in 0..(param_n - param_f + 1) {
                inboxes.push(network::SimulationInbox::new());
            }
            // let mut inboxes_ptrs: Vec<&mut network::SimulationInbox> = inboxes.iter_mut().collect();

            for r in param_sim_horizon.clone() {
                let t: goldfish_type::Slot = (r as goldfish_type::Slot) / 4;
                let phase = (r as goldfish_type::Slot) % 4;
                log::warn!("Main loop: r={} t={} phase={}", r, t, phase);

                {
                    let mut inboxes = inboxes.clone();
                    thread::spawn(move || {
                        for inbox in inboxes.iter_mut() {
                            inbox.deliver_msgs_inflight(r);
                        }
                    })
                    .join()
                    .unwrap();
                }

                {
                    let mut inboxes = inboxes.clone();
                    adversary = thread::spawn(move || {
                        adversary.step(&lotteries, r, &mut inboxes, (param_n - param_f) as usize);
                        adversary
                    })
                    .join()
                    .unwrap();
                }

                let mut handles = vec![];
                for inbox_id in 0..(param_n - param_f) {
                    let handle = {
                        let mut inboxes = inboxes.clone();
                        let mut this_validator = validators.remove(0);
                        thread::spawn(move || {
                            this_validator.step(&lotteries, r, &mut inboxes, inbox_id as usize);
                            this_validator
                        })
                    };
                    handles.push(handle);
                }
                for handle in handles {
                    validators.push(handle.join().unwrap());
                }
            }

            // STATS
            log::warn!("Stats");

            #[derive(Debug, Clone, Copy, Serialize, Deserialize)]
            struct Stats {
                r: usize,
                n_asleep: usize,
                n_awake: usize,
                n_honest_asleep: usize,
                n_honest_dreamy: usize,
                n_honest_awake: usize,
                n_adversary: usize,
                n_all: usize,
                #[serde(flatten, with = "prefix_party0_ledger")]
                party0_ledger: goldfish_validator::ValidatorLedgerStats,
                #[serde(flatten, with = "prefix_party0_comms")]
                party0_comms: network::CommunicationStats,
                #[serde(flatten, with = "prefix_party1_ledger")]
                party1_ledger: goldfish_validator::ValidatorLedgerStats,
                #[serde(flatten, with = "prefix_party1_comms")]
                party1_comms: network::CommunicationStats,
                #[serde(flatten, with = "prefix_party2_ledger")]
                party2_ledger: goldfish_validator::ValidatorLedgerStats,
                #[serde(flatten, with = "prefix_party2_comms")]
                party2_comms: network::CommunicationStats,
                #[serde(flatten, with = "prefix_party3_ledger")]
                party3_ledger: goldfish_validator::ValidatorLedgerStats,
                #[serde(flatten, with = "prefix_party3_comms")]
                party3_comms: network::CommunicationStats,
                #[serde(flatten, with = "prefix_party4_ledger")]
                party4_ledger: goldfish_validator::ValidatorLedgerStats,
                #[serde(flatten, with = "prefix_party4_comms")]
                party4_comms: network::CommunicationStats,
                #[serde(flatten, with = "prefix_party_alwaysawake_ledger")]
                party_alwaysawake_ledger: goldfish_validator::ValidatorLedgerStats,
                #[serde(flatten, with = "prefix_party_alwaysawake_comms")]
                party_alwaysawake_comms: network::CommunicationStats,
            }

            with_prefix!(prefix_party0_ledger "party0_");
            with_prefix!(prefix_party0_comms "party0_comms_");
            with_prefix!(prefix_party1_ledger "party1_");
            with_prefix!(prefix_party1_comms "party1_comms_");
            with_prefix!(prefix_party2_ledger "party2_");
            with_prefix!(prefix_party2_comms "party2_comms_");
            with_prefix!(prefix_party3_ledger "party3_");
            with_prefix!(prefix_party3_comms "party3_comms_");
            with_prefix!(prefix_party4_ledger "party4_");
            with_prefix!(prefix_party4_comms "party4_comms_");
            with_prefix!(prefix_party_alwaysawake_ledger "partyALWAYSAWAKE_");
            with_prefix!(prefix_party_alwaysawake_comms "partyALWAYSAWAKE_comms_");

            let idx_always_awake = da_schedules
                .par_iter()
                .position_first(|da_schedule| {
                    da_schedule.iter().all(|da_schedule_status| {
                        *da_schedule_status == goldfish_validator::DaScheduleStatus::Awake
                    })
                })
                .unwrap();
            assert!(da_schedules
                .iter()
                .all(|da_schedule| da_schedule.len() == param_r_horizon + 4));
            let n_asleep: HashMap<usize, usize> =
                HashMap::from_iter(param_sim_horizon.clone().map(|r| {
                    (
                        r,
                        da_schedules
                            .par_iter()
                            .filter(|da_schedule| {
                                da_schedule[r] == goldfish_validator::DaScheduleStatus::Asleep
                            })
                            .count(),
                    )
                }));
            let n_awake: HashMap<usize, usize> =
                HashMap::from_iter(param_sim_horizon.clone().map(|r| {
                    (
                        r,
                        da_schedules
                            .par_iter()
                            .filter(|da_schedule| {
                                da_schedule[r] == goldfish_validator::DaScheduleStatus::Awake
                            })
                            .count(),
                    )
                }));
            let n_honest_asleep: HashMap<usize, usize> =
                HashMap::from_iter(param_sim_horizon.clone().map(|r| {
                    (
                        r,
                        validators
                            .par_iter()
                            .filter(|val| {
                                val.stats().get(&r).unwrap().0.status
                                    == goldfish_validator::DaValidatorSleepStatus::Asleep
                            })
                            .count(),
                    )
                }));
            let n_honest_dreamy: HashMap<usize, usize> =
                HashMap::from_iter(param_sim_horizon.clone().map(|r| {
                    (
                        r,
                        validators
                            .par_iter()
                            .filter(|val| {
                                val.stats().get(&r).unwrap().0.status
                                    == goldfish_validator::DaValidatorSleepStatus::Dreamy
                            })
                            .count(),
                    )
                }));
            let n_honest_awake: HashMap<usize, usize> =
                HashMap::from_iter(param_sim_horizon.clone().map(|r| {
                    (
                        r,
                        validators
                            .par_iter()
                            .filter(|val| {
                                val.stats().get(&r).unwrap().0.status
                                    == goldfish_validator::DaValidatorSleepStatus::Awake
                            })
                            .count(),
                    )
                }));

            let records: Vec<Stats> = param_sim_horizon
                .map(|r| Stats {
                    r,
                    n_asleep: n_asleep[&r],
                    n_awake: n_awake[&r],
                    n_honest_asleep: n_honest_asleep[&r],
                    n_honest_dreamy: n_honest_dreamy[&r],
                    n_honest_awake: n_honest_awake[&r],
                    n_adversary: param_f as usize,
                    n_all: param_n as usize,
                    party0_ledger: validators[0].stats().get(&r).unwrap().1,
                    party0_comms: *inboxes[0].stats().get(&r).unwrap(),
                    party1_ledger: validators[1].stats().get(&r).unwrap().1,
                    party1_comms: *inboxes[1].stats().get(&r).unwrap(),
                    party2_ledger: validators[2].stats().get(&r).unwrap().1,
                    party2_comms: *inboxes[2].stats().get(&r).unwrap(),
                    party3_ledger: validators[3].stats().get(&r).unwrap().1,
                    party3_comms: *inboxes[3].stats().get(&r).unwrap(),
                    party4_ledger: validators[4].stats().get(&r).unwrap().1,
                    party4_comms: *inboxes[4].stats().get(&r).unwrap(),
                    party_alwaysawake_ledger: validators[idx_always_awake]
                        .stats()
                        .get(&r)
                        .unwrap()
                        .1,
                    party_alwaysawake_comms: *inboxes[idx_always_awake].stats().get(&r).unwrap(),
                })
                .collect();

            let mut wtr = csv::Writer::from_writer(std::io::stdout());
            for record in records {
                wtr.serialize(record)?;
            }
            wtr.flush()?;

            println!("");

            println!("{}", validators[0].dump_dotfile());

            println!("");

            println!(
                "ALWAYS AWAKE final ledgers: {} {} {} {} {} {}",
                validators[idx_always_awake].stats()[&(param_r_horizon + 4 - 1)]
                    .1
                    .ledger_best
                    .length,
                validators[idx_always_awake].stats()[&(param_r_horizon + 4 - 1)]
                    .1
                    .ledger_best
                    .age,
                validators[idx_always_awake].stats()[&(param_r_horizon + 4 - 1)]
                    .1
                    .ledger_fast
                    .length,
                validators[idx_always_awake].stats()[&(param_r_horizon + 4 - 1)]
                    .1
                    .ledger_fast
                    .age,
                validators[idx_always_awake].stats()[&(param_r_horizon + 4 - 1)]
                    .1
                    .ledger_slow
                    .length,
                validators[idx_always_awake].stats()[&(param_r_horizon + 4 - 1)]
                    .1
                    .ledger_slow
                    .age,
            );
            println!(
                "ALWAYS AWAKE total communication: {} {}",
                inboxes[idx_always_awake]
                    .stats()
                    .iter()
                    .map(|(_, v)| v.all_size)
                    .sum::<usize>(),
                inboxes[idx_always_awake]
                    .stats()
                    .iter()
                    .map(|(_, v)| v.all_count)
                    .sum::<usize>()
            );
            println!(
                "ALWAYS AWAKE blocks communication: {} {}",
                inboxes[idx_always_awake]
                    .stats()
                    .iter()
                    .map(|(_, v)| v.piece_block_size)
                    .sum::<usize>(),
                inboxes[idx_always_awake]
                    .stats()
                    .iter()
                    .map(|(_, v)| v.piece_block_count)
                    .sum::<usize>()
            );
            println!(
                "ALWAYS AWAKE votes communication: {} {}",
                inboxes[idx_always_awake]
                    .stats()
                    .iter()
                    .map(|(_, v)| v.piece_vote_size)
                    .sum::<usize>(),
                inboxes[idx_always_awake]
                    .stats()
                    .iter()
                    .map(|(_, v)| v.piece_vote_count)
                    .sum::<usize>()
            );
            println!(
                "ALWAYS AWAKE proposals communication: {} {}",
                inboxes[idx_always_awake]
                    .stats()
                    .iter()
                    .map(|(_, v)| v.proposal_size)
                    .sum::<usize>(),
                inboxes[idx_always_awake]
                    .stats()
                    .iter()
                    .map(|(_, v)| v.proposal_count)
                    .sum::<usize>()
            );

            Ok(())
        }
    }
}
