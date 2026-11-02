"""Isolation preflight must reject shared controller resources before spawning."""
import json
import os
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from enclave_gateway.security.isolation import PrincipalRouter
from enclave_gateway.security.policy import AccessPolicy,Grant


class RouterPreflightTests(unittest.TestCase):
    def fixture(self,root):
        grants={name:Grant(name,('enclave_status',),nodes=('@appliance','@bastion')) for name in ('alice','bob')}
        mapping={}
        for index,(name,grant) in enumerate(grants.items()):
            folder=root/name;folder.mkdir()
            config={'appliance':{'hypervisor':'direct'},'provider':{'type':'custom'},'bastion':{'appliance_spool_dir':f'C:\\lab\\{name}'},
                    'security':{'worker_account':f'S-1-5-21-1000-1000-1000-{1001+index}','worker_sha256':'c'*64,'runtime_sha256':'e'*64,
                                'trusted_signers':['D'*40],'enforce_worker_attestation':True,'require_process_isolation':True,'owned_ssh_commands':True}}
            (folder/'config.json').write_text(json.dumps(config))
            (folder/'policy.json').write_text(json.dumps({'principals':{name:{'tools':list(grant.tools),'nodes':list(grant.nodes)}}}))
            mapping[name]={'identity':'uid:'+str(20001+index),'config':str(folder/'config.json'),'policy':str(folder/'policy.json'),'state_dir':str(folder/'state')}
        file=root/'map.json';file.write_text(json.dumps({'principals':mapping}))
        return file,mapping,AccessPolicy(grants)

    def test_distinct_readonly_profiles_pass_without_starting_workers(self):
        with TemporaryDirectory() as temp:
            file,mapping,policy=self.fixture(Path(temp))
            router=PrincipalRouter(file,policy=policy)
            self.assertEqual(router._backends,{})
            router.close()

    def test_shared_identity_state_or_spool_is_rejected(self):
        with TemporaryDirectory() as temp:
            file,mapping,policy=self.fixture(Path(temp))
            original=json.loads(json.dumps(mapping))
            for field in ('identity','state_dir'):
                mapping=json.loads(json.dumps(original));mapping['bob'][field]=mapping['alice'][field]
                file.write_text(json.dumps({'principals':mapping}))
                with self.subTest(field=field),self.assertRaises(ValueError): PrincipalRouter(file,policy=policy)
            file.write_text(json.dumps({'principals':original}))
            cfg=Path(original['bob']['config']);data=json.loads(cfg.read_text());data['bastion']['appliance_spool_dir']=r'C:\lab\alice';cfg.write_text(json.dumps(data))
            with self.assertRaises(ValueError): PrincipalRouter(file,policy=policy)

    def test_windows_utf8_bom_maps_policies_and_unicode_config_load_consistently(self):
        from enclave_gateway.config import EnclaveConfig
        with TemporaryDirectory() as temp:
            file,mapping,policy=self.fixture(Path(temp))
            file.write_text(file.read_text(),encoding='utf-8-sig')
            for spec in mapping.values():
                config=Path(spec['config']);value=json.loads(config.read_text());value['profile']='fixture-тест'
                config.write_text(json.dumps(value,ensure_ascii=False),encoding='utf-8-sig')
                p=Path(spec['policy']);p.write_text(p.read_text(),encoding='utf-8-sig')
                self.assertEqual(EnclaveConfig.load(config).profile,'fixture-тест')
            router=PrincipalRouter(file,policy=policy)
            self.assertEqual(router._backends,{})
            router.close()
