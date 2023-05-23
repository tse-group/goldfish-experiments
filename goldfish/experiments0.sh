#! /bin/bash -ve

EXID=experiment0

EXSUBID=A
for pblock in 0.0030
do
    RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 50 --n 100 --probability-lottery-block $pblock --probability-lottery-vote 0.1 iid-participation --fraction-iid 0.8 --fraction-participation-lb 0.1 | tee experiments/$EXID-$EXSUBID-$pblock.log
done

EXSUBID=B
for pblock in 0.0030
do
    RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 50 --n 100 --probability-lottery-block $pblock --probability-lottery-vote 0.1 momose-ren-participation --fraction-warmup 0.1 --fraction-crement 0.01 --fraction-low-participation-lb 0.1 --fraction-low-participation-ub 0.3 --fraction-high-participation-lb 0.7 --fraction-high-participation-ub 0.9 | tee experiments/$EXID-$EXSUBID-$pblock.log
done

EXSUBID=C
for pblock in 0.0030
do
    RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 50 --n 100 --probability-lottery-block $pblock --probability-lottery-vote 0.1 momose-ren-participation --fraction-warmup 0.1 --fraction-crement 0.01 --fraction-low-participation-lb 0.1 --fraction-low-participation-ub 0.3 --fraction-high-participation-lb 0.7 --fraction-high-participation-ub 0.9 | tee experiments/$EXID-$EXSUBID-$pblock.log
done

