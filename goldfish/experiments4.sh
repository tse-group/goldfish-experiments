#! /bin/bash -ve

EXID=experiment4

EXSUBID=A
for pblock in 0.0010 0.0030 0.0050 0.0150
do
    RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 75 --n 1000 --probability-lottery-block $pblock --probability-lottery-vote 0.1 iid-participation --fraction-iid 0.8 --fraction-participation-lb 0.1 | tee experiments/$EXID-$EXSUBID-$pblock.log
done

# EXSUBID=B
# for pblock in 0.0010 0.0030 0.0050 0.0150
# do
#     RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 75 --n 1000 --probability-lottery-block $pblock --probability-lottery-vote 0.1 momose-ren-participation --fraction-warmup 0.1 --fraction-crement 0.01 --fraction-low-participation-lb 0.1 --fraction-low-participation-ub 0.3 --fraction-high-participation-lb 0.7 --fraction-high-participation-ub 0.9 | tee experiments/$EXID-$EXSUBID-$pblock.log
# done

EXSUBID=C
for pblock in 0.0010 0.0030 0.0050 0.0150
do
    RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 120 --n 1000 --probability-lottery-block $pblock --probability-lottery-vote 0.1 momose-ren-participation --fraction-warmup 0.1 --fraction-crement 0.01 --fraction-low-participation-lb 0.1 --fraction-low-participation-ub 0.3 --fraction-high-participation-lb 0.7 --fraction-high-participation-ub 0.9 | tee experiments/$EXID-$EXSUBID-$pblock.log
done

EXSUBID=D
for pblock in 0.0010 0.0030 0.0050 0.0150
do
    RUST_BACKTRACE=full cargo +nightly run --release -- -v simulate --t-horizon 120 --n 1000 --probability-lottery-block $pblock --probability-lottery-vote 0.1 momose-ren-participation --fraction-warmup 0.1 --fraction-crement 0.03 --fraction-low-participation-lb 0.1 --fraction-low-participation-ub 0.3 --fraction-high-participation-lb 0.7 --fraction-high-participation-ub 0.9 | tee experiments/$EXID-$EXSUBID-$pblock.log
done

