#!/usr/bin/env python3
"""Show available campaign targets."""
import json
from collections import Counter
data = json.loads(open('benchmarks/campaign_targets_top100.json', encoding='utf-8').read())
langs = Counter(e.get('language', '?') for e in data['entries'])
print('Languages:', dict(langs))
print()
for e in data['entries'][:15]:
    print(f"  {e['id']:45s} {e['language']:10s} {e.get('status','?'):10s}")
