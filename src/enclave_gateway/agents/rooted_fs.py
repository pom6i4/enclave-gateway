"""Descriptor-relative file protocol. Executable standalone on a POSIX Python 3 host."""
from __future__ import annotations
import base64
import contextlib
import hashlib
import fnmatch
import json
import os
import re
import stat

MAX_CHUNK = 192 * 1024
MAX_FILES = 10000


def components(path):
    if not isinstance(path,str) or '\\' in path or '\0' in path:
        raise ValueError('Invalid relative path')
    parts=path.split('/') if path else []
    if any(part in ('','.','..') or ':' in part for part in parts):
        raise ValueError('Invalid relative path')
    return parts


class RootedFS:
    def __init__(self, root):
        if os.name == 'nt':
            raise RuntimeError('Use the signed native filesystem helper on Windows')
        if not os.path.isabs(root): raise ValueError('Root must be absolute')
        self.fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
        try:
            for part in components(root.strip('/')):
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.fd)
                os.close(self.fd); self.fd=child
        except BaseException:
            os.close(self.fd); raise

    def close(self): os.close(self.fd)
    def __enter__(self): return self
    def __exit__(self,*_): self.close()

    @contextlib.contextmanager
    def directory(self,path='',create=False):
        fd=os.dup(self.fd)
        try:
            for part in components(path):
                if create:
                    try: os.mkdir(part,0o700,dir_fd=fd)
                    except FileExistsError: pass
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd); fd=child
            yield fd
        finally: os.close(fd)

    @contextlib.contextmanager
    def file(self,path,flags=os.O_RDONLY):
        parts=components(path)
        if not parts: raise ValueError('File name required')
        with self.directory('/'.join(parts[:-1])) as parent:
            fd=os.open(parts[-1],flags|os.O_NOFOLLOW|os.O_NONBLOCK,0o600,dir_fd=parent)
            try:
                info=os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise ValueError('Only regular unlinked files are supported')
                yield fd
            finally: os.close(fd)

    def list(self,path='',exclude=()):
        result=[]
        def walk(relative):
            with self.directory(relative) as fd:
                for name in sorted(os.listdir(fd)):
                    components(name)
                    child=(relative+'/' if relative else '')+name
                    if any(fnmatch.fnmatch(child,pattern) or any(fnmatch.fnmatch(part,pattern) for part in child.split('/')) for pattern in exclude): continue
                    info=os.stat(name,dir_fd=fd,follow_symlinks=False)
                    if stat.S_ISDIR(info.st_mode):
                        result.append({'path':child,'kind':'dir'}); walk(child)
                    elif stat.S_ISREG(info.st_mode) and info.st_nlink==1:
                        with self.file(child) as stream:
                            digest=hashlib.sha256()
                            while chunk:=os.read(stream,MAX_CHUNK): digest.update(chunk)
                        result.append({'path':child,'kind':'file','size':info.st_size,'sha256':digest.hexdigest(),'mode':info.st_mode&0o777})
                    else: raise ValueError('Links and special files are forbidden')
                    if len(result)>MAX_FILES: raise ValueError('Tree exceeds file limit')
        walk(path)
        return result

    def read(self,path,offset,size):
        if type(offset) is not int or offset<0 or type(size) is not int or not 1<=size<=MAX_CHUNK: raise ValueError('Invalid read geometry')
        with self.file(path) as fd:
            os.lseek(fd,offset,os.SEEK_SET)
            return os.read(fd,size)

    def write(self,path,offset,data):
        if type(offset) is not int or offset<0 or len(data)>MAX_CHUNK: raise ValueError('Invalid write geometry')
        parts=components(path)
        with self.directory('/'.join(parts[:-1]),create=True): pass
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL if offset==0 else os.O_WRONLY
        with self.file(path,flags) as fd:
            if os.fstat(fd).st_size != offset: raise ValueError('Stage offset mismatch')
            os.lseek(fd,offset,os.SEEK_SET)
            view=memoryview(data)
            while view: view=view[os.write(fd,view):]
            os.fsync(fd)

    def commit(self,stage,target,digest,mode=0o600):
        if type(mode) is not int or not 0<=mode<=0o777: raise ValueError('Invalid file mode')
        if not re.fullmatch('[a-f0-9]{64}',digest): raise ValueError('Invalid digest')
        with self.file(stage) as fd:
            actual=hashlib.sha256()
            while chunk:=os.read(fd,MAX_CHUNK): actual.update(chunk)
            if actual.hexdigest()!=digest: raise ValueError('Stage digest mismatch')
            os.fchmod(fd,mode); os.fsync(fd)
        source=components(stage); destination=components(target)
        # replace operates on directory entries; the destination is never opened/followed.
        with self.directory('/'.join(source[:-1])) as source_fd, self.directory('/'.join(destination[:-1]),create=True) as target_fd:
            os.replace(source[-1],destination[-1],src_dir_fd=source_fd,dst_dir_fd=target_fd)
            os.fsync(target_fd)

    def remove(self,path):
        parts=components(path)
        with self.directory('/'.join(parts[:-1])) as fd:
            try: os.unlink(parts[-1],dir_fd=fd)
            except FileNotFoundError: pass


def request(value):
    with RootedFS(value['root']) as fs:
        action=value['action']; path=value.get('path','')
        if action=='list': return {'entries':fs.list(path,value.get('exclude',()))}
        if action=='mkdir':
            with fs.directory(path,create=True): pass
        elif action=='read': return {'data':base64.b64encode(fs.read(path,value['offset'],value.get('size',MAX_CHUNK))).decode()}
        elif action=='write': fs.write(path,value['offset'],base64.b64decode(value['data'],validate=True))
        elif action=='commit': fs.commit(path,value['target'],value['sha256'],value.get('mode',0o600))
        elif action=='remove': fs.remove(path)
        else: raise ValueError('Unsupported filesystem action')
        return {'ok':True}


if __name__=='__main__':
    import sys
    try:
        raw=sys.stdin.buffer.read(1024*1024+1)
        if len(raw)>1024*1024: raise ValueError('Request too large')
        print(json.dumps(request(json.loads(raw))))
    except Exception:
        print(json.dumps({'error':'rooted_filesystem_failed'})); sys.exit(1)
