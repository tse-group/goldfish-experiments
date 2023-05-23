#! /usr/bin/env python3

import os
import re

for f in os.listdir('.'):
    match = re.findall(r'(experiment(\d+)-(.*)).log', f)
    if match:
        print("Processing", f, match)
        d = open(f, 'r').readlines()

        csv, dot, stats = [], [], []
        output = [csv, dot, [], stats]

        state = 0
        for l in d:
            if l.strip() == '':
                state += 1
                continue
            
            output[state].append(l)
        
        csv = [ l.replace(',', ' ') for l in csv ]

        open('processed/timeline-' + match[0][0] + '.txt', 'w').write(''.join(csv))
        open('processed/dot-' + match[0][0] + '.txt', 'w').write(''.join(dot))
        open('processed/stats-' + match[0][0] + '.txt', 'w').write(''.join(stats))
