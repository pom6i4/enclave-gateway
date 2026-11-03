#!/usr/bin/env python3
"""Fixed short-command gate; preserves failed samples and never trims outliers."""
from __future__ import annotations
import argparse
import json
import math
from pathlib import Path
import statistics

LIMIT_MS = 800
MIN_SAMPLES = 30


def qualify(receipt):
    cohorts = receipt.get('cohorts')
    if not isinstance(cohorts, dict) or not cohorts:
        raise ValueError('A nonempty cohorts mapping is required')
    results = {}
    for name, rows in cohorts.items():
        if not isinstance(rows, list):
            raise ValueError('Each cohort must contain the complete sample list')
        values = []
        failures = []
        for index, row in enumerate(rows):
            value = row.get('elapsed_ms') if isinstance(row, dict) else None
            valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
            if valid:
                values.append(value)
            if not valid or row.get('ok') is not True or value > LIMIT_MS:
                failures.append(index)
        results[name] = {'samples': len(rows), 'failed_indices': failures,
                         'median_ms': statistics.median(values) if values else None,
                         'max_ms': max(values) if values else None,
                         'passed': len(rows) >= MIN_SAMPLES and not failures}
    return {'status': 'passed' if all(v['passed'] for v in results.values()) else 'failed',
            'limit_ms': LIMIT_MS, 'minimum_samples': MIN_SAMPLES, 'cohorts': results,
            'scope': receipt.get('scope', 'unspecified; no deployment acceptance inferred')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError('Preserve previous gate results; choose a new output')
    result = qualify(json.loads(args.input.read_text()))
    with args.output.open('x', encoding='utf-8') as stream:
        json.dump(result, stream, indent=2)
    print(json.dumps(result))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
