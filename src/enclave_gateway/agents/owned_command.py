"""POSIX command supervisor with an authenticated private cancellation socket."""
from __future__ import annotations
import base64
import hashlib
import hmac
import json
import os
import selectors
import signal
import socket
import stat
import subprocess
import time
from pathlib import Path


def exit_observer():
    if callable(getattr(os,'waitid',None)):
        return lambda pid:os.waitid(os.P_PID,pid,os.WEXITED|os.WNOHANG|os.WNOWAIT) is not None
    # Some supported macOS CPython distributions omit the Python waitid
    # binding. Keep the unreaped child identity through the native OS API.
    import ctypes
    import sys
    if sys.platform=='darwin':flags=1|4|32
    elif sys.platform.startswith('linux'):flags=1|4|0x01000000
    else:raise RuntimeError('Owned commands require non-reaping waitid support')
    api=ctypes.CDLL(None,use_errno=True)
    wait=api.waitid;wait.argtypes=[ctypes.c_uint,ctypes.c_uint,ctypes.c_void_p,ctypes.c_int];wait.restype=ctypes.c_int
    def observed(pid):
        # Both ABIs put si_signo first. The buffer exceeds siginfo_t on these
        # platforms, and a nonblocking call leaves its zeroed signal unchanged
        # when there is no child status. WNOWAIT never releases the PID.
        info=ctypes.create_string_buffer(256)
        if wait(1,pid,info,flags):raise OSError(ctypes.get_errno(),'Could not observe owned child')
        return ctypes.c_int.from_buffer(info).value!=0
    return observed


def endpoint(token):
    if not isinstance(token,str) or len(token)!=64 or any(c not in '0123456789abcdef' for c in token): raise ValueError('Invalid token')
    directory=Path('/tmp')/('egw-owned-'+str(os.getuid()))
    try: directory.mkdir(mode=0o700)
    except FileExistsError: pass
    info=directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=os.getuid() or info.st_mode&0o077: raise PermissionError('Unsafe supervisor directory')
    return directory/(hashlib.sha256(token.encode()).hexdigest()[:40]+'.sock')


def cancel(token):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as client:
        client.settimeout(2)
        try: client.connect(str(endpoint(token)))
        except FileNotFoundError: return {'cancel_requested':False,'reason':'supervisor_not_present'}
        client.sendall(token.encode()); client.shutdown(socket.SHUT_WR)
        return {'cancel_requested':client.recv(16)==b'accepted'}


def execute(value):
    observe_exit=exit_observer()
    path=endpoint(value['token']); started=time.monotonic()
    timeout=float(value['timeout_sec'])
    if not 0<timeout<=86400: raise ValueError('Invalid deadline')
    output=bytearray(); errors=bytearray(); cancelled=False; expired=False; stopped=False
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
        listener.bind(str(path)); os.chmod(path,0o600); listener.listen(4); listener.setblocking(False)
        with selectors.DefaultSelector() as selector:
            # Read the entire script from a private pipe before evaluating it.
            # This preserves EOF stdin for payload commands and avoids argv limits
            # without writing scripts or credentials to temporary files.
            process=subprocess.Popen(['sh','-c','eval "$(cat)"'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,start_new_session=True)
            script_data=value['script'].encode('utf-8');script_offset=0
            os.set_blocking(process.stdin.fileno(),False)
            if script_data:selector.register(process.stdin,selectors.EVENT_WRITE,'input')
            else:process.stdin.close()
            selector.register(listener,selectors.EVENT_READ,'cancel')
            for stream,label in ((process.stdout,'out'),(process.stderr,'err')):
                os.set_blocking(stream.fileno(),False); selector.register(stream,selectors.EVENT_READ,label)
            def stop():
                # The leader has not been reaped here; its PID cannot be reused.
                nonlocal stopped
                try: os.killpg(process.pid,signal.SIGKILL); stopped=True
                except ProcessLookupError: stopped=True
                except PermissionError:
                    # Darwin can return EPERM for a group containing only zombies.
                    # Keep an earlier successful kill acknowledgement; otherwise
                    # report uncertainty instead of masking the command's result.
                    pass
            try:
                exited=False
                while not exited or len(selector.get_map())>1:
                    # WNOWAIT observes exit without releasing the PID/PGID identity.
                    exited=observe_exit(process.pid)
                    if exited: stop()
                    if time.monotonic()-started>=timeout:
                        expired=True; stop()
                    for key,_ in selector.select(0.05):
                        if key.data=='input':
                            try:script_offset+=os.write(key.fileobj.fileno(),script_data[script_offset:script_offset+65536])
                            except BrokenPipeError:script_offset=len(script_data)
                            if script_offset==len(script_data):selector.unregister(key.fileobj);key.fileobj.close()
                            continue
                        if key.data=='cancel':
                            client,_=listener.accept()
                            with client:
                                client.settimeout(0.2)
                                token=client.recv(65)
                                if hmac.compare_digest(token,value['token'].encode()):
                                    cancelled=True; stop(); client.sendall(b'accepted')
                            continue
                        data=os.read(key.fileobj.fileno(),65536)
                        if data:
                            target=output if key.data=='out' else errors
                            target.extend(data)
                            if len(output)+len(errors)>16*1024*1024: raise ValueError('Command output limit exceeded')
                        else:
                            selector.unregister(key.fileobj); key.fileobj.close()
                stop()  # terminate any background descendants before reaping the leader
                code=process.wait(timeout=5)
            finally:
                stop()
                process.wait(timeout=5)
                for stream in (process.stdin,process.stdout,process.stderr):
                    if not stream.closed: stream.close()
                path.unlink(missing_ok=True)
    return {'exit_code':125 if cancelled else 124 if expired else code,
            'stdout_b64':base64.b64encode(output).decode(),'stderr_b64':base64.b64encode(errors).decode(),
            'owned_tree_stopped':stopped,'cancelled':cancelled,'timed_out':expired}


if __name__=='__main__':
    import sys
    try:
        value=json.loads(sys.stdin.buffer.read(1024*1024+1))
        result=cancel(value['token']) if value['action']=='cancel' else execute(value)
        print(json.dumps(result))
    except Exception:
        print('{"error":"owned_command_failed"}'); sys.exit(1)
