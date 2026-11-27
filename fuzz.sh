#!/bin/bash

mkdir -p fuzz
echo "ratio,seed,rc" > fuzz/results.csv

for r in 0.004 0.01 0.05 0.2; do
    for s in $(seq 1 200); do
        zzuf -s $s -r $r < test.conf > fuzz/input.conf
        ./exchange --config fuzz/input.conf --dump-config > /dev/null 2>&1
        rc=$?
        echo "$r,$s,$rc" >> fuzz/results.csv
        if [ $rc -ge 128 ]; then
            cp fuzz/input.conf fuzz/crash_r${r}_s${s}.conf
            echo "crash: ratio=$r seed=$s rc=$rc"
        fi
    done
done

echo "rc counts:"
tail -n +2 fuzz/results.csv | cut -d, -f3 | sort -n | uniq -c
