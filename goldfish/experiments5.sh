#! /bin/bash -ve

EXID=experiment5

EXSUBID=A
for pblock in 0.0030
do
    RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 120 --n 1000 --probability-lottery-block $pblock --probability-lottery-vote 0.1 full-participation | tee experiments/$EXID-$EXSUBID-$pblock.log
done
