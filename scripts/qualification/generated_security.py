#!/usr/bin/env python3
"""Seeded authorization, RPC and proxy inputs with replayable counterexamples."""
from __future__ import annotations
import argparse
import copy
import ipaddress
import json
from pathlib import Path
import random
import secrets
import socket
import struct
import sys
import threading
import time
from tempfile import TemporaryDirectory
from unittest.mock import Mock

ROOT=Path(__file__).resolve().parents[2];sys.path[:0]=[str(ROOT/'src'),str(Path(__file__).resolve().parent)]
from enclave_gateway.audit.flight_recorder import FlightRecorder
from enclave_gateway.config import EnclaveConfig
from enclave_gateway.engine import EnclaveEngine
from enclave_gateway.mcp_server.server import McpJsonRpcServer,McpHttpServer
from enclave_gateway.operations.context import OperationError
from enclave_gateway.security.policy import AccessPolicy,Grant,below
from enclave_gateway.security.secrets import SecretVault
from enclave_gateway.transports.socks5_mux import negotiate_proxy_destination
from enclave_gateway.transports.rdp_vfs import pump_mux_connection
from enclave_gateway.hypervisor.state import atomic_json
from full_acceptance import cohort_sources


def check(condition,sample):
    if not condition:
        error=AssertionError('Generated security counterexample');error.sample=sample;raise error


def minimize_sequence(values,fails):
    """Delta-debug a failing sequence; every accepted reduction is replayed."""
    values=list(values);width=max(1,len(values)//2)
    while values:
        reduced=False
        for start in range(0,len(values),width):
            candidate=values[:start]+values[start+width:]
            if fails(candidate):values=candidate;reduced=True;break
        if reduced:continue
        if width==1:break
        width=max(1,width//2)
    return values


def path_cases(rng,count):
    roots=['/srv/allowed',r'C:\allowed']
    bad=['../escape','x/../../escape','x\x00y','%TEMP%/escape']
    for case in range(count):
        windows=bool(rng.randrange(2));root=roots[windows];sep='\\' if windows else '/'
        child='item_'+str(rng.randrange(1000));kind=rng.randrange(5)
        value=root+sep+child;expected=True
        if kind==1:value=root+'-other'+sep+child;expected=False
        elif kind==2:value=root+sep+rng.choice(bad);expected=False
        elif kind==3 and windows:value=root+sep+rng.choice(['NUL','CON.txt','COM1','file:stream','tail.','tail ']);expected=False
        elif kind==4:value=child;expected=False
        check(below(value,[root])==expected,{'model':'paths','case':case,'path':value,'root':root,'expected':expected})


def destination_cases(rng,count):
    policy=AccessPolicy({'viewer':Grant('viewer',('enclave_tunnel',),destinations=('10.0.0.0/24','2001:db8::/64'))})
    grant=policy.grant('viewer')
    for case in range(count):
        host=rng.choice(['10.0.0.'+str(rng.randrange(256)),'10.0.1.'+str(rng.randrange(256)),
                         '2001:db8::'+format(rng.randrange(65536),'x'),'bastion.enclave.internal','127.0.0.1'])
        port=rng.choice([0,1,22,3389,65535,65536,True,'22'])
        expected=type(port) is int and 1<=port<=65535
        try:address=ipaddress.ip_address(host);expected=expected and any(address in ipaddress.ip_network(n) for n in grant.destinations)
        except ValueError:expected=False
        try:policy.authorize_destination(grant,host,port);actual=True
        except OperationError:actual=False
        check(actual==expected,{'model':'destinations','case':case,'host':host,'port':port,'expected':expected})


def rpc_cases(rng,count,root):
    control=Mock();engine=EnclaveEngine(EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'provider':{'type':'custom'}}),
            control_override=control,vault=SecretVault(env_file=root/'absent.env'),recorder=FlightRecorder(root/'audit.jsonl'))
    policy=AccessPolicy({'viewer':Grant('viewer',('enclave_capabilities',))})
    server=McpJsonRpcServer(engine,policy=policy,principal='viewer')
    requests=[]
    for case in range(count):
        request=rng.choice([None,[],True,{'jsonrpc':'2.0','id':case,'method':'tools/call','params':{'name':'node_exec','arguments':{'node':'@appliance','script':'forbidden','actor':'administrator'}}},
            {'jsonrpc':'2.0','id':case,'method':'tools/call','params':{'name':'node_exec','arguments':{'node':'@appliance','script':'forbidden'}}},
            {'jsonrpc':'2.0','id':case,'method':'tools/call','params':{'name':['node_exec'],'arguments':{}}},
            {'jsonrpc':'2.0','id':case,'method':'tools/call','params':{'name':'node_exec','arguments':rng.choice([[],True,'invalid',None])}},
            {'jsonrpc':'2.0','id':{'owner':'administrator'},'method':'tools/list'},
            {'jsonrpc':'2.0','id':case,'method':'tools/list','params':rng.choice([True,1,'invalid'])}])
        request=copy.deepcopy(request);requests.append(request)
        try:response=server.handle_message(request)
        except Exception as cause:
            error=AssertionError('RPC input escaped protocol error handling');error.sample={'model':'rpc','case':case,'request':request};raise error from cause
        check(isinstance(response,dict) and 'error' in response,{'model':'rpc','case':case,'request':request,'response':response})
        check(not control.mock_calls,{'model':'rpc-dispatch','case':case,'request':request})
    # Concurrent denied batches must not inherit another caller's authority.
    responses=[]
    def deny(index):responses.append(server.handle_message({'jsonrpc':'2.0','id':index,'method':'tools/call','params':{'name':'node_exec','arguments':{'node':'@appliance','script':'forbidden'}}}))
    threads=[threading.Thread(target=deny,args=(n,)) for n in range(16)]
    for thread in threads:thread.start()
    for thread in threads:thread.join(5)
    check(len(responses)==16 and all('error' in r for r in responses) and not control.mock_calls,{'model':'concurrent-rpc-denial'})


def http_cases(rng,count,root):
    control=Mock();engine=EnclaveEngine(EnclaveConfig.from_dict({'appliance':{'hypervisor':'direct'},'provider':{'type':'custom'}}),
            control_override=control,vault=SecretVault(env_file=root/'absent.env'),recorder=FlightRecorder(root/'http-audit.jsonl'))
    policy=AccessPolicy({'viewer':Grant('viewer',('enclave_capabilities',))})
    rpc=McpJsonRpcServer(engine,policy=policy,principal='viewer');token=secrets.token_hex(16)
    server=McpHttpServer(rpc,bind_port=0,principal_tokens={token:'viewer'})
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    deadline=time.monotonic()+5
    while server._httpd is None:
        if not thread.is_alive() or time.monotonic()>deadline:raise RuntimeError('HTTP fixture startup failed')
        time.sleep(.005)
    authority='127.0.0.1:'+str(server.bind_port)
    def request(headers,body,path='/tools/node_exec'):
        raw=('POST '+path+' HTTP/1.1\r\n'+'\r\n'.join(headers)+'\r\n\r\n').encode()+body
        with socket.create_connection(('127.0.0.1',server.bind_port),timeout=3) as connection:
            connection.sendall(raw);connection.shutdown(socket.SHUT_WR);response=bytearray()
            while chunk:=connection.recv(8192):
                response.extend(chunk)
                if len(response)>1024*1024:raise ValueError('Unbounded HTTP fixture response')
        return int(bytes(response).split(b' ',2)[1])
    try:
        for case in range(count):
            body=b'{"node":"@appliance","script":"forbidden"}'
            headers=['Host: '+authority,'Authorization: Bearer '+token,'Content-Type: application/json','Content-Length: '+str(len(body))]
            variant=rng.randrange(7);expected=403
            if variant==1:headers[1]='Authorization: Bearer invalid';expected=401
            elif variant==2:headers.append('Authorization: Bearer '+token);expected=401
            elif variant==3:headers.append('Host: '+authority)
            elif variant==4:headers.append('Origin: https://untrusted.invalid')
            elif variant==5:headers.append('Content-Length: '+str(len(body)));expected=400
            elif variant==6:body=b'{invalid';headers[-1]='Content-Length: '+str(len(body));expected=400
            code=request(headers,body)
            check(code==expected and not control.mock_calls,{'model':'http','case':case,'variant':variant,'expected':expected,'actual':code})
        code=request(['Host: '+authority,'Authorization: Bearer '+token,'Content-Type: application/json','Content-Length: 2'],b'{}','/tools/enclave_capabilities')
        check(code==200 and not control.mock_calls,{'model':'http-recovery','status':code})
    finally:
        server.stop();thread.join(5)
        if thread.is_alive():raise RuntimeError('HTTP fixture thread remains')


class Fragments:
    def __init__(self,data,rng):self.data=data;self.rng=rng;self.replies=[]
    def recv(self,n):
        n=min(n,self.rng.randrange(1,13));value,self.data=self.data[:n],self.data[n:];return value
    def settimeout(self,*_):pass
    def sendall(self,data):self.replies.append(data)


def proxy_cases(rng,count):
    for case in range(count):
        host='10.0.0.'+str(rng.randrange(1,255));port=rng.randrange(1,65536);kind=rng.randrange(3)
        if kind==0:data=b'\x05\x01\x00\x05\x01\x00\x01'+socket.inet_aton(host)+struct.pack('!H',port);protocol='socks5'
        elif kind==1:data=b'\x04\x01'+struct.pack('!H',port)+socket.inet_aton(host)+b'fixture\x00';protocol='socks4'
        else:data=('CONNECT '+host+':'+str(port)+' HTTP/1.1\r\nHost: '+host+'\r\n\r\n').encode();protocol='http_connect'
        result=negotiate_proxy_destination(Fragments(data,rng))
        check(result==(host,port,protocol,b''),{'model':'proxy-fragments','case':case,'wire_hex':data.hex(),'expected':[host,port,protocol]})
    for data in [b'\x05\x01\x00\x05\x01\x01\x01',b'CONNECT invalid HTTP/1.1\r\n\r\n',
                 b'POST http://10.0.0.10/ HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n']:
        try:negotiate_proxy_destination(Fragments(data,rng))
        except (ValueError,EOFError,PermissionError):pass
        else:check(False,{'model':'proxy-invalid','wire_hex':data.hex()})


def mux_case(chunks,quantum):
    class Client:
        def __init__(self):self.input=list(chunks)+[b''];self.output=bytearray();self.shutdowns=[]
        def settimeout(self,*_):pass
        def recv(self,n):return self.input.pop(0)
        def sendall(self,data):self.output.extend(data)
        def shutdown(self,how):self.shutdowns.append(how)
    class Remote:
        def __init__(self):self.pending=bytearray();self.half_closed=False;self.shutdowns=0;self.closed=0;self.calls=0
        def mux_io(self,conn,data,**_):
            self.calls+=1
            if self.calls>10000:raise ValueError('Mux fixture failed to drain')
            assert not self.half_closed or not data
            self.pending.extend(data);result=bytes(self.pending[:quantum]);del self.pending[:quantum]
            return result,self.half_closed and not self.pending
        def mux_shutdown_write(self,conn):self.half_closed=True;self.shutdowns+=1
        def mux_close(self,conn):self.closed+=1
    client=Client();remote=Remote();pump_mux_connection(remote,client,'fixture')
    return bytes(client.output)==b''.join(chunks) and remote.shutdowns==remote.closed==1 and client.shutdowns==[socket.SHUT_WR]


def mux_cases(rng,count):
    for case in range(count):
        chunks=[rng.randbytes(rng.randrange(1,65)) for _ in range(rng.randrange(1,9))];quantum=rng.randrange(1,33)
        if not mux_case(chunks,quantum):
            reduced=minimize_sequence(chunks,lambda values:not mux_case(values,quantum))
            check(False,{'model':'mux-half-close','case':case,'chunks_hex':[c.hex() for c in chunks],
                         'minimized_chunks_hex':[c.hex() for c in reduced],'read_quantum':quantum})


def run(output,seeds=(17,9173,65537),cases=200):
    if output.exists():raise FileExistsError('Preserve generated security evidence')
    output.mkdir(parents=True,mode=0o700);sources=cohort_sources()
    report={'status':'running','scope':'seeded-security-models','sources':sources,'seeds':list(seeds),'cases_per_model_per_seed':cases,'models':['paths','destinations','rpc','proxy-fragments','http','mux-half-close']}
    try:
        for seed in seeds:
            report['active_seed']=seed;rng=random.Random(seed);root=output/str(seed);root.mkdir()
            path_cases(rng,cases);destination_cases(rng,cases);rpc_cases(rng,cases,root);proxy_cases(rng,cases);http_cases(rng,cases,root);mux_cases(rng,cases)
        if cohort_sources()!=sources:raise RuntimeError('Source changed during models')
        report['status']='passed'
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__)
        if getattr(error,'sample',None):report['counterexample']=error.sample
        raise
    finally:atomic_json(output/'result.json',report)
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);p.add_argument('--seed',type=int,action='append');p.add_argument('--cases',type=int,default=200);a=p.parse_args()
    if not 1<=a.cases<=10000:p.error('cases must be 1..10000')
    print(json.dumps(run(a.output,a.seed or (17,9173,65537),a.cases),indent=2))
