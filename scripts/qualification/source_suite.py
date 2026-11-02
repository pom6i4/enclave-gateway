#!/usr/bin/env python3
"""Run the ordinary source suite with explicit platform, skips and source binding."""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import sys
import time
import unittest

ROOT=Path(__file__).resolve().parents[2]
sys.path[:0]=[str(ROOT/'src'),str(Path(__file__).resolve().parent)]
from full_acceptance import cohort_sources
from enclave_gateway.hypervisor.state import atomic_json


def run(output):
    output=output.resolve()
    if output.exists():raise FileExistsError('Preserve previous source-suite evidence')
    output.mkdir(parents=True,mode=0o700)
    sources=cohort_sources()
    report={'status':'running','scope':'ordinary-source-suite','sources':sources,
            'platform':{'system':platform.system(),'machine':platform.machine(),'python':platform.python_version()},
            'optional_tools':{},'observer_budgets':{
                'powershell_parser_sec':float(os.environ.get('EGW_TEST_POWERSHELL_TIMEOUT_SEC','30')),
                'crash_checkpoint_sec':float(os.environ.get('EGW_TEST_CRASH_OBSERVER_SEC','30'))}}
    if any(not 30<=value<=240 for value in report['observer_budgets'].values()):raise ValueError('Invalid fixture observer budget')
    for name in ('EGW_TEST_POWERSHELL','EGW_TEST_DOTNET','EGW_TEST_HELPER'):
        value=os.environ.get(name)
        report['optional_tools'][name]={'enabled':bool(value)}
        if value:report['optional_tools'][name]['sha256']=hashlib.sha256(Path(value).read_bytes()).hexdigest()
    atomic_json(output/'result.json',report);started=time.monotonic()
    try:
        suite=unittest.defaultTestLoader.discover(str(ROOT/'tests'))
        with (output/'tests.log').open('x',encoding='utf-8') as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
        report.update(tests=result.testsRun,skips=[{'test':t.id(),'reason':reason} for t,reason in result.skipped],
                      failures=[t.id() for t,_ in result.failures],errors=[t.id() for t,_ in result.errors],
                      log_sha256=hashlib.sha256((output/'tests.log').read_bytes()).hexdigest())
        if not result.wasSuccessful():raise RuntimeError('Ordinary source suite failed')
        if not result.testsRun:raise ValueError('Empty source suite')
        if cohort_sources()!=sources:raise RuntimeError('Source changed during source suite')
        report['status']='passed'
    except BaseException as error:report.update(status='failed',error_type=type(error).__name__);raise
    finally:
        report['elapsed_sec']=round(time.monotonic()-started,3);atomic_json(output/'result.json',report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    print(json.dumps(run(p.parse_args().output),indent=2))
