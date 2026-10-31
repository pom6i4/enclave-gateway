"""Retention must never erase the identity of an executed operation."""
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from enclave_gateway.operations.journal import TransactionJournal
from enclave_gateway.operations.retention import RetentionPolicy
from enclave_gateway.operations.context import OperationError


class RetentionTests(unittest.TestCase):
    def test_utf8_byte_limit_and_legacy_paged_maintenance(self):
        with TemporaryDirectory() as root:
            journal=TransactionJournal(Path(root)/'journal.sqlite3',RetentionPolicy(max_payload_bytes=100,interval_seconds=99999))
            journal._last_maintenance=time.monotonic()
            journal.reserve('unicode','alice','exec','app01','hash',10)
            journal.update('unicode','alice','completed',result={'value':'я'*60})
            self.assertEqual(journal.get('unicode','alice')['payload_status'],'archived')
            with journal.connect() as db:
                db.executemany("INSERT INTO transactions (tx_id,principal,operation,node,fingerprint,state,created,updated,expires,result) VALUES (?,'alice','exec','app01','hash','completed',1,1,2,'{}')",(('old'+str(index),) for index in range(300)))
            journal.retention=RetentionPolicy(max_results=1,max_age_seconds=0)
            result=journal.maintain(force=True)
            self.assertEqual(result['archived_results'],300)
            self.assertEqual(journal.get('old299','alice')['payload_status'],'archived')
            self.assertEqual(journal.reserve('old0','alice','exec','app01','hash',10)['state'],'completed')

    def test_archive_readback_expiry_and_tombstones(self):
        with TemporaryDirectory() as root:
            journal=TransactionJournal(Path(root)/'journal.sqlite3',RetentionPolicy(max_results=1,archive_seconds=86400,interval_seconds=99999))
            for index in range(3):
                tx='tx'+str(index)
                journal.reserve(tx,'alice','exec','app01','hash',10)
                journal.update(tx,'alice','completed',result={'kind':'mapping','value':{'index':index}})
            journal.retention=RetentionPolicy(max_results=1,archive_seconds=86400)
            result=journal.maintain(force=True)
            self.assertEqual(journal.get('tx0','alice')['payload_status'],'archived')
            self.assertEqual(journal.get('tx0','alice')['result']['value']['index'],0)
            self.assertEqual(journal.get('tx0','alice')['payload_status'],'archived')
            self.assertIsNone(journal.get('tx0','bob'))
            journal.retention=RetentionPolicy(max_results=1,archive_seconds=0)
            journal.maintain(force=True)
            old=journal.reserve('tx0','alice','exec','app01','hash',10)
            self.assertEqual(old['payload_status'],'expired')
            self.assertEqual(old['state'],'completed')
            self.assertEqual(len(journal.recent('alice')),3)
            self.assertIsNone(journal.get('tx0','bob'))

    def test_unresolved_work_and_identity_capacity_survive_maintenance(self):
        with TemporaryDirectory() as root:
            journal=TransactionJournal(Path(root)/'journal.sqlite3',RetentionPolicy(max_age_seconds=0,max_identities=2))
            journal.reserve('running','alice','exec','app01','hash',10)
            journal.reserve('unknown','alice','exec','app01','hash',10)
            journal.update('unknown','alice','indeterminate',error={'code':'unknown'})
            journal.maintain(force=True)
            self.assertEqual(journal.get('unknown','alice')['error'],{'code':'unknown'})
            self.assertEqual(journal.get('unknown','alice')['state'],'indeterminate')
            self.assertEqual(journal.get('running','alice')['payload_status'],'retained')
            with self.assertRaises(OperationError) as caught:
                journal.reserve('new','alice','exec','app01','hash',10)
            self.assertEqual(caught.exception.code,'journal_capacity')

    def test_archive_tampering_fails_closed_without_replay(self):
        with TemporaryDirectory() as root:
            journal=TransactionJournal(Path(root)/'journal.sqlite3',RetentionPolicy(max_age_seconds=0))
            journal.reserve('old','alice','exec','app01','hash',10)
            journal.update('old','alice','completed',result={'value':'fixture'})
            journal.maintain(force=True)
            archive=next(journal.path.with_suffix('.archives').glob('*.jsonl'))
            archive.write_text('{}\n')
            row=journal.reserve('old','alice','exec','app01','hash',10)
            self.assertEqual(row['payload_status'],'archive_unavailable')
            self.assertEqual(row['state'],'completed')
