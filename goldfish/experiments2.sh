#! /bin/bash -ve

# this experiment was run before the block size was fixed to 80KB

RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 225 --n 1000 --probability-lottery-block 0.0005 --probability-lottery-vote 0.1 simple-alternating-participation --periods 2 --low-participation 0.1 | tee experiments/experiment2-A-0.0005.log
RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 225 --n 1000 --probability-lottery-block 0.00075 --probability-lottery-vote 0.1 simple-alternating-participation --periods 2 --low-participation 0.1 | tee experiments/experiment2-A-0.00075.log
RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 225 --n 1000 --probability-lottery-block 0.001 --probability-lottery-vote 0.1 simple-alternating-participation --periods 2 --low-participation 0.1 | tee experiments/experiment2-A-0.001.log
RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 225 --n 1000 --probability-lottery-block 0.0025 --probability-lottery-vote 0.1 simple-alternating-participation --periods 2 --low-participation 0.1 | tee experiments/experiment2-A-0.0025.log
RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 225 --n 1000 --probability-lottery-block 0.005 --probability-lottery-vote 0.1 simple-alternating-participation --periods 2 --low-participation 0.1 | tee experiments/experiment2-A-0.005.log
RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 225 --n 1000 --probability-lottery-block 0.0075 --probability-lottery-vote 0.1 simple-alternating-participation --periods 2 --low-participation 0.1 | tee experiments/experiment2-A-0.0075.log
RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 225 --n 1000 --probability-lottery-block 0.01 --probability-lottery-vote 0.1 simple-alternating-participation --periods 2 --low-participation 0.1 | tee experiments/experiment2-A-0.01.log
RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 225 --n 1000 --probability-lottery-block 0.025 --probability-lottery-vote 0.1 simple-alternating-participation --periods 2 --low-participation 0.1 | tee experiments/experiment2-A-0.025.log
RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 225 --n 1000 --probability-lottery-block 0.05 --probability-lottery-vote 0.1 simple-alternating-participation --periods 2 --low-participation 0.1 | tee experiments/experiment2-A-0.05.log
