#! /usr/bin/env python3

import os
import re

print("pblock ledger_best_len ledger_best_age ledger_fast_len ledger_fast_age ledger_slow_len ledger_slow_age comms_total_size comms_total_count comms_blocks_size comms_blocks_count comms_votes_size comms_votes_count comms_proposals_size comms_proposals_count")

lst = os.listdir('processed')
lst.sort()
for f in lst:
    match = re.findall(r'stats-(experiment3-A-(.*)).txt', f)
    if match:
        # print("Processing", f, match)
        d = open('processed/' + f, 'r').readlines()
        assert(len(d) == 5)

        print(*[match[0][1],] + [l.split(':')[1].strip() for l in d])
