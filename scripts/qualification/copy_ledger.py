#!/usr/bin/env python3
"""Read a private worker-ledger snapshot without contacting a deployment."""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import re

PART_BYTES = 1024*1024
MAX_BYTES = 512*PART_BYTES


def analyze(directory, operation_id):
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError('Select a plain private ledger snapshot directory')
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', operation_id):
        raise ValueError('Select an exact operation identity')
    files = sorted(directory.glob('*.json'))
    if not files or len(files)>50000:
        raise ValueError('Empty or excessive ledger snapshot')
    actions = {key:0 for key in ('push_part','pull_part','push_commit','pull_info')}
    states = {key:0 for key in ('running','completed','failed','indeterminate','cancelled')}
    offsets = []
    identities = set()
    incomplete = 0
    inputs = {}
    for path in files:
        if path.is_symlink() or path.stat().st_size>2*1024*1024:
            raise ValueError('Linked or excessive ledger record')
        raw = path.read_bytes()
        value = json.loads(raw.decode('utf-8-sig'))
        if not isinstance(value,dict):
            raise ValueError('Malformed ledger record')
        if value.get('operation_id') != operation_id:
            continue
        inputs[path.name] = hashlib.sha256(raw).hexdigest()
        identity=value.get('tx_id')
        if not isinstance(identity,str) or identity in identities:
            raise ValueError('Missing or duplicate worker request identity')
        identities.add(identity)
        state=value.get('state')
        if state not in states:
            raise ValueError('Unknown ledger outcome')
        states[state]+=1
        action=value.get('copy_action')
        if action not in actions:
            incomplete+=1
            continue
        actions[action]+=1
        if action in ('push_part','pull_part'):
            offset=value.get('copy_offset')
            if type(offset) is not int or not 0<=offset<MAX_BYTES or offset%PART_BYTES:
                raise ValueError('Invalid or ambiguous data-block offset')
            offsets.append(offset)
    if not identities:
        raise ValueError('Selected operation not found in ledger snapshot')
    indices=sorted({offset//PART_BYTES+1 for offset in offsets})
    report={'scope':'offline-ledger-offset-analysis','ledger_records':len(identities),
            'action_counts':actions,'state_counts':states,'records_without_copy_action':incomplete,
            'unique_data_blocks_observed':len(indices),'repeated_data_offsets':len(offsets)-len(indices),
            'highest_data_block_observed':max(indices,default=0),
            'missing_before_highest':[i for i in range(1,max(indices,default=0)+1) if i not in indices],
            'counter_basis':'one-based data block from copy_offset / 1048576 + 1',
            'failing_block':'not inferred from record count or highest observed offset',
            'response_slot_is_data_block_index':False,'contains_deployment_identifiers':False}
    return report, inputs


if __name__ == '__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ledger',required=True,type=Path)
    parser.add_argument('--operation-id',required=True)
    parser.add_argument('--output',required=True,type=Path,help='New private evidence directory.')
    args=parser.parse_args()
    report,inputs=analyze(args.ledger,args.operation_id)
    args.output.mkdir(parents=True,mode=0o700,exist_ok=False)
    (args.output/'private-inputs.json').write_text(json.dumps(inputs,indent=2)+'\n')
    (args.output/'result.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))
