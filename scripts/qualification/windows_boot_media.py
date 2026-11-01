"""Select the installation ISO's own noprompt EFI image in a derived lab ISO."""
from __future__ import annotations
import hashlib
import os
import shutil
import struct
import subprocess
import sys
from pathlib import Path


def prepare(source: Path,destination: Path):
    if destination.exists():raise FileExistsError('Derived boot media already exists')
    tool=shutil.which('7z') or shutil.which('7zz')
    if not tool:raise FileNotFoundError('7-Zip is required to read the official ISO component')
    # Extraction reads one vendor-provided boot image, never arbitrary members
    # or filesystem paths from an archive into the Host.
    component='efi/microsoft/boot/efisys_noprompt.bin'
    image=subprocess.check_output([tool,'x','-so',str(source),component],stderr=subprocess.PIPE,timeout=90)
    if len(image)!=1474560 or image[510:512]!=b'\x55\xaa':raise ValueError('Unsupported vendor EFI boot image')
    catalog=None
    with source.open('rb') as stream:
        for sector in range(16,64):
            stream.seek(sector*2048);descriptor=stream.read(2048)
            if descriptor[1:6]!=b'CD001':raise ValueError('Invalid ISO descriptor')
            if descriptor[0]==0 and descriptor[7:39].rstrip(b'\0 ') == b'EL TORITO SPECIFICATION':
                catalog=struct.unpack_from('<I',descriptor,71)[0];break
            if descriptor[0]==255:break
        if catalog is None:raise ValueError('No El Torito catalog')
        stream.seek(catalog*2048);table=bytearray(stream.read(2048))
    if table[0]!=1 or table[30:32]!=b'\x55\xaa' or sum(struct.unpack('<16H',table[:32]))%65536:raise ValueError('Invalid boot catalog validation entry')
    candidates=[];offset=64
    while offset+32<=len(table):
        header=table[offset:offset+32]
        if header[0] not in (0x90,0x91):break
        count=struct.unpack_from('<H',header,2)[0]
        if not 0<count<=30 or offset+32+count*32>len(table):raise ValueError('Unsupported boot section')
        for index in range(count):
            entry=offset+32+index*32
            if header[1]==0xef and table[entry]==0x88 and table[entry+1]==0:candidates.append(entry)
        offset+=32+count*32
        if header[0]==0x91:break
    if len(candidates)!=1:raise ValueError('Expected exactly one EFI no-emulation entry')
    original_component=subprocess.check_output([tool,'x','-so',str(source),'efi/microsoft/boot/efisys.bin'],stderr=subprocess.PIPE,timeout=90)
    entry=candidates[0];image_sector=struct.unpack_from('<I',table,entry+8)[0]
    with source.open('rb') as stream:
        stream.seek(image_sector*2048);original=stream.read(len(image))
    if len(original_component)!=len(image) or original!=original_component:raise ValueError('EFI boot extent does not match the vendor component')
    if sys.platform=='darwin':
        result=subprocess.run(['/bin/cp','-c',str(source),str(destination)],capture_output=True)
        if result.returncode:shutil.copyfile(source,destination)
    else:shutil.copyfile(source,destination)
    destination.chmod(0o600)
    try:
        with destination.open('r+b') as stream:
            # Replace only the existing, same-size EFI FAT boot extent with the
            # ISO's own noprompt variant. Catalog, UDF extents and all installer
            # payloads retain their original offsets and bytes.
            stream.seek(image_sector*2048);stream.write(image);stream.flush();os.fsync(stream.fileno())
        return {'status':'prepared','scope':'derived-lab-boot-media','component':component,
                'efi_component_sha256':hashlib.sha256(image).hexdigest(),'source_bytes':source.stat().st_size,
                'changed_original_range':[image_sector*2048,image_sector*2048+len(image)],
                'secure_boot_policy':'unchanged-vendor-efi-component'}
    except BaseException:
        destination.unlink(missing_ok=True);raise
