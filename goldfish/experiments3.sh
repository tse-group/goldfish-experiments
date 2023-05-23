#! /bin/bash -ve

EXID=experiment3

EXSUBID=A
for pblock in 0.0002 0.0004 0.0006 0.0008 0.0010 0.0012 0.0014 0.0016 0.0018 0.0020 0.0025 0.0035 0.0050 0.0075 0.0100
do
    RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 75 --n 1000 --probability-lottery-block $pblock --probability-lottery-vote 0.1 full-participation | tee experiments/$EXID-$EXSUBID-$pblock.log
done

EXSUBID=B
for pblock in 0.0005 0.0010 0.0020 0.0030 0.0025 0.0050 0.0100 0.0150
do
    RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 75 --n 1000 --probability-lottery-block $pblock --probability-lottery-vote 0.1 simple-alternating-participation --periods 2 --low-participation 0.2 | tee experiments/$EXID-$EXSUBID-$pblock.log
done

