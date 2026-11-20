"""Distinguish worker records, data offsets and redirected-stream slot numbers."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('copy_ledger',ROOT/'scripts/qualification/copy_ledger.py')
ledger=importlib.util.module_from_spec(spec)
spec.loader.exec_module(ledger)


class CopyLedgerTests(unittest.TestCase):
    def record(self,root,number,action,offset=0):
        value={'tx_id':'request_'+str(number),'operation_id':'fixture','state':'completed',
               'copy_action':action,'copy_offset':offset,'remote_path':'/private/fixture','policy_sha256':'a'*64}
        (root/f'{number}.json').write_text(json.dumps(value))

    def test_75_records_are_not_data_block_75_or_response_slot_123(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            self.record(root,0,'pull_info')
            for index in range(74):self.record(root,index+1,'pull_part',index*1048576)
            report,inputs=ledger.analyze(root,'fixture')
            self.assertEqual(report['ledger_records'],75)
            self.assertEqual(report['unique_data_blocks_observed'],74)
            self.assertEqual(report['highest_data_block_observed'],74)
            self.assertFalse(report['response_slot_is_data_block_index'])
            self.assertNotIn('private',json.dumps(report))
            self.assertNotIn('fixture',json.dumps(report))
            self.assertEqual(len(inputs),75)

    def test_gaps_and_duplicate_offsets_are_visible(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for n,offset in enumerate((0,2*1048576,2*1048576)):self.record(root,n,'push_part',offset)
            report,_=ledger.analyze(root,'fixture')
            self.assertEqual(report['missing_before_highest'],[2])
            self.assertEqual(report['repeated_data_offsets'],1)

    def test_partial_records_do_not_invent_an_offset(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            (root/'running.json').write_text(json.dumps({'tx_id':'request','operation_id':'fixture','state':'running'}))
            report,_=ledger.analyze(root,'fixture')
            self.assertEqual(report['records_without_copy_action'],1)
            self.assertEqual(report['highest_data_block_observed'],0)
            with self.assertRaises(ValueError):ledger.analyze(root,'absent')


if __name__=='__main__':unittest.main()
