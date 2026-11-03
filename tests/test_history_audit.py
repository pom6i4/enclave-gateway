"""History review sees removed material without echoing it or changing Git refs."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
_spec=importlib.util.spec_from_file_location('history_audit',ROOT/'scripts/release/audit_history.py')
audit=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(audit)


class HistoryAuditTests(unittest.TestCase):
    def git(self,root,*args):
        return subprocess.check_output(['git','-C',str(root),*args],stderr=subprocess.DEVNULL)

    def prepare(self,root):
        self.git(root,'init','-q')
        self.git(root,'config','user.name','Roman Kuligin')
        self.git(root,'config','user.email','91665362+pom6i4@users.noreply.github.com')
        self.git(root,'config','commit.gpgsign','false')
        (root/'fixture.txt').write_text('ghp_'+'A'*36)
        self.git(root,'add','fixture.txt');self.git(root,'commit','-qm','Add synthetic fixture')
        (root/'fixture.txt').unlink()
        self.git(root,'add','-u');self.git(root,'commit','-qm','Remove synthetic fixture')

    def test_removed_credential_pattern_is_detected_and_never_emitted(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.prepare(root);before=audit.inventory(root)[1];report=audit.scan(root)
            self.assertEqual(report['commits_scanned'],2);self.assertEqual(report['status'],'review_required')
            self.assertTrue(any(row['rule']=='github-token' for row in report['findings']))
            self.assertNotIn('ghp_'+'A'*36,json.dumps(report));self.assertEqual(before,audit.inventory(root)[1])
            output=root/'private-report.json';audit.write_report(output,report)
            with self.assertRaises(FileExistsError):audit.write_report(output,report)
            if os.name!='nt':self.assertEqual(output.stat().st_mode&0o777,0o600)

    def test_explicit_review_is_complete_and_bound_to_exact_inventory(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.prepare(root);report=audit.scan(root)
            decision={'revision':1,'inventory_sha256':report['inventory_sha256'],
                      'decisions':[{'id':row['id'],'disposition':'synthetic-test-fixture','reason':'Synthetic repeated bytes in the fixture generator'} for row in report['findings']]}
            self.assertEqual(audit.review(report,decision)['status'],'passed')
            self.assertEqual(audit.review(report,{**decision,'decisions':[]})['status'],'review_required')
            with self.assertRaises(ValueError):audit.review(report,{**decision,'inventory_sha256':'0'*64})
            with self.assertRaises(ValueError):audit.review(report,{**decision,'decisions':decision['decisions']*2})
            bad={**decision['decisions'][0],'disposition':{}}
            with self.assertRaises(ValueError):audit.review(report,{**decision,'decisions':[bad]})

    def test_removed_binary_is_retained_as_a_finding(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.prepare(root);(root/'fixture.msi').write_bytes(b'MZ'+bytes(2)+b'fixture')
            self.git(root,'add','fixture.msi');self.git(root,'commit','-qm','Add synthetic binary')
            (root/'fixture.msi').unlink();self.git(root,'add','-u');self.git(root,'commit','-qm','Remove synthetic binary')
            report=audit.scan(root)
            self.assertTrue(any(row['rule']=='forbidden-path' and row['paths']==['fixture.msi'] for row in report['findings']))
            self.assertTrue(any(row['rule']=='binary-object-needs-review' for row in report['findings']))

    def test_unreachable_commit_metadata_is_not_silently_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d);self.prepare(root);message='Co-'+'Authored-'+'By: synthetic fixture'
            self.git(root,'commit','--allow-empty','-qm',message)
            self.git(root,'reset','--hard','HEAD~1')
            report=audit.scan(root)
            self.assertEqual(report['commits_scanned'],3)
            self.assertTrue(any(row['rule'].startswith('attribution-') for row in report['findings']))
            self.assertNotIn(message,json.dumps(report))
