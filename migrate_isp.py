#!/usr/bin/env python3
"""Migrate existing ISP VMs to EcoRouter without deleting VMs or old disks.

Python 3.9+ and Proxmox VE 7/8. The default action is a read-only plan.
VM protection stays unchanged. Migrated VMs remain stopped for manual setup.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse, unquote
from urllib.request import urlopen

DEFAULT_URL='https://disk.yandex.ru/d/WHdIBzZls5HZtQ/EcoRouter.qcow2'
DEFAULT_SHA256='3acf519eb775603cf53475dafb1db800ee18aca1ecd4ddd09589f92fe9aba481'
MAX_IMAGE=16*1024**3
MAC_RESERVATIONS=set()
DISK=re.compile(r'^(?:(?:ide|sata|scsi|virtio)\d+|efidisk0|tpmstate0)$')
RESTORABLE=frozenset(('bios','machine','cpu','cores','memory','cpulimit','cpuunits',
                     'serial0','tablet','agent','net0','net1','net2','net3','boot','sockets','balloon'))

class Error(RuntimeError):
    pass

def redact(message):
    message=re.sub(r'(https?://[^\s?]+)\?[^\s]+',r'\1?<redacted>',str(message))
    return re.sub(r'(?i)(Bearer\s+|token[=: ]+)[^\s]+',r'\1<redacted>',message)

class Runner:
    def __call__(self,*args,timeout=60):
        result=subprocess.run([str(a) for a in args],stdin=subprocess.DEVNULL,
            text=True,encoding='utf-8',errors='replace',stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,timeout=timeout,check=False)
        if result.returncode:
            raise Error(redact(result.stderr.strip() or result.stdout.strip()
                              or 'Command failed: '+' '.join(map(str,args))))
        return result.stdout.strip()

def parse_config(raw):
    result={}
    for line in raw.splitlines():
        if line.strip().startswith('['): break
        if not line or line.lstrip().startswith('#'): continue
        if ': ' not in line: raise Error('Unexpected VM configuration line')
        key,value=line.split(': ',1)
        if key in result: raise Error('Duplicate configuration key: '+key)
        result[key]=value
    return result

def fingerprint(cfg):
    data={k:str(v) for k,v in cfg.items() if k!='digest'}
    return hashlib.sha256(json.dumps(data,sort_keys=True,separators=(',',':')).encode()).hexdigest()

def is_isp_name(name):
    return bool(re.search(r'(?:^|[-_])ISP$',name or '',re.I))

def parse_network(value):
    parts=str(value).split(',')
    if not parts or '=' not in parts[0]: raise Error('Adapter has no explicit model/MAC')
    model,mac=parts[0].split('=',1)
    options={}
    for part in parts[1:]:
        if '=' not in part: raise Error('Malformed network option')
        key,val=part.split('=',1)
        if key in options: raise Error('Duplicate network option: '+key)
        options[key]=val
    if not options.get('bridge'): raise Error('Adapter has no bridge')
    return model,mac,options

def random_mac():
    for _ in range(10000):
        mac='1C:87:76:40:'+':'.join(f'{b:02X}' for b in secrets.token_bytes(2))
        if mac not in MAC_RESERVATIONS:
            MAC_RESERVATIONS.add(mac)
            return mac
    raise Error('EcoRouter MAC address pool is exhausted')

def network_sources(cfg,override=None):
    nets={k:v for k,v in cfg.items() if re.fullmatch(r'net\d+',k)}
    if len(nets)>4: raise Error('More than four adapters: manual topology review required')
    if any(key not in {'net0','net1','net2','net3'} for key in nets):
        raise Error('Adapter indices outside net0..3 require manual review')
    if override:
        mapping={role:('net'+str(value) if str(value).isdigit() else str(value)) for role,value in override.items()}
        if set(mapping)!={'wan','hq','br'} or len(set(mapping.values()))!=3:
            raise Error('Explicit WAN/HQ/BR mappings must be distinct')
        if any(key not in nets for key in mapping.values()): raise Error('Mapped adapter is missing')
    elif set(nets)=={'net0','net1','net2'}:
        if parse_network(nets['net0'])[2].get('link_down')=='1':
            raise Error('Three adapters with disabled net0 are ambiguous')
        mapping={'wan':'net0','hq':'net1','br':'net2'}
    elif set(nets)=={'net0','net1','net2','net3'}:
        if parse_network(nets['net0'])[2].get('link_down')!='1':
            raise Error('Four adapters require disabled service net0 or explicit mapping')
        mapping={'wan':'net1','hq':'net2','br':'net3'}
    else: raise Error('Expected net0..2 or service net0 plus net1..3')
    for key in mapping.values(): parse_network(nets[key])
    return mapping

def build_networks(cfg,mac_factory=None,override=None):
    mapping=network_sources(cfg,override)
    factory=mac_factory or random_mac
    used=set()
    def render(options):
        for _ in range(100):
            mac=factory().upper()
            if not re.fullmatch(r'1C:87:76:40:[0-9A-F]{2}:[0-9A-F]{2}',mac):
                raise Error('EcoRouter MAC must have prefix 1C:87:76:40')
            if mac not in used:
                used.add(mac)
                return 'vmxnet3='+mac+','+','.join(f'{k}={v}' for k,v in options.items())
        raise Error('Cannot generate distinct MAC addresses')
    mgmt=dict(parse_network(cfg[mapping['wan']])[2]); mgmt['link_down']='1'
    result={'net0':render(mgmt)}
    for target,role in (('net1','wan'),('net2','hq'),('net3','br')):
        options=dict(parse_network(cfg[mapping[role]])[2])
        if role=='wan': options.pop('link_down',None)
        result[target]=render(options)
    return result

def disk_values(cfg):
    return {k:v for k,v in cfg.items() if DISK.fullmatch(k)}

def os_disks(cfg):
    return {k:v for k,v in disk_values(cfg).items() if k not in ('efidisk0','tpmstate0')
            and 'media=cdrom' not in v and 'cloudinit' not in v and not v.startswith('none')}

def effective_original_boot(cfg):
    boot=cfg.get('boot','')
    if boot.startswith('order='):
        order=boot[6:].split(',')[0].split(';')
        if not any(key in os_disks(cfg) for key in order):
            raise Error('Original boot order contains no OS disk')
        return boot
    old_disk=cfg.get('bootdisk')
    if old_disk and old_disk in os_disks(cfg): return 'order='+old_disk
    disks=os_disks(cfg)
    if len(disks)==1: return 'order='+next(iter(disks))
    raise Error('Original OS boot disk is ambiguous; define boot order first')

def build_plan(vmid,cfg,status,storage,mac_factory=None,override=None,machine='pc-i440fx-7.0'):
    if not is_isp_name(cfg.get('name','')): raise Error('Target name must be ISP or end in -ISP/_ISP')
    if status not in ('running','stopped'): raise Error('VM must be running or stopped')
    if cfg.get('lock'): raise Error('VM is locked: '+str(cfg['lock']))
    if str(cfg.get('sockets','1'))!='1' or ('vcpus' in cfg and str(cfg['vcpus'])!='2'):
        raise Error('Nonstandard socket/vCPU configuration requires manual review')
    if any(k in ('args','hookscript','tpmstate0') or re.fullmatch(r'(?:hostpci|usb)\d+',k) for k in cfg):
        raise Error('Custom QEMU args, hooks, TPM or passthrough require manual review')
    if not os_disks(cfg): raise Error('Original OS disk not found')
    slot=next((f'ide{i}' for i in range(4) if f'ide{i}' not in cfg),None)
    if slot is None: raise Error('All IDE slots occupied; no disk will be detached')
    if isinstance(storage,str): storage={'storage':storage,'type':'dir','avail':0}
    if not isinstance(storage,dict) or not storage.get('storage'): raise Error('Storage missing')
    if storage.get('type') not in ('dir','lvmthin','zfspool'):
        raise Error('Supported storage types: dir, lvmthin, zfspool')
    updates={'bios':'seabios','machine':machine,'cpu':'host','cores':'2','memory':'4096',
             'cpulimit':'1','cpuunits':'75','serial0':'socket','tablet':'0','agent':'0',
             'boot':'order='+slot,'sockets':'1','balloon':'0'}
    updates.update(build_networks(cfg,mac_factory,override))
    return {'vmid':int(vmid),'original_config':dict(cfg),'original_status':status,
            'before_fingerprint':fingerprint(cfg),'new_config':updates,'ide_slot':slot,
            'storage':dict(storage),'protection':str(cfg.get('protection','0')),
            'source_networks':network_sources(cfg,override),
            'original_effective_boot':effective_original_boot(cfg)}

def validate_mutation_plan(plan,expected_vmid=None):
    if not isinstance(plan,dict): raise Error('Invalid migration plan')
    vmid=plan.get('vmid')
    if not isinstance(vmid,int) or isinstance(vmid,bool) or not 100<=vmid<=999999999:
        raise Error('Invalid planned VMID')
    if expected_vmid is not None and vmid!=int(expected_vmid): raise Error('Planned VMID differs')
    original=plan.get('original_config')
    if not isinstance(original,dict) or not is_isp_name(original.get('name','')):
        raise Error('Original target is not ISP')
    slot=plan.get('ide_slot','')
    if not isinstance(slot,str) or not re.fullmatch(r'ide[0-3]',slot) or slot in original:
        raise Error('New disk slot is not a free IDE slot in original configuration')
    updates=plan.get('new_config')
    if not isinstance(updates,dict) or not set(updates)<=RESTORABLE:
        raise Error('Unsafe configuration key in saved migration plan')
    if updates.get('boot')!='order='+slot: raise Error('Unsafe planned boot order')
    if not {'net0','net1','net2','net3'}<=set(updates): raise Error('Four planned NICs are required')
    macs=set()
    for key in ('net0','net1','net2','net3'):
        model,mac,options=parse_network(updates[key])
        if model!='vmxnet3' or not re.fullmatch(r'1C:87:76:40:[0-9A-F]{2}:[0-9A-F]{2}',mac.upper()):
            raise Error('Unsafe planned EcoRouter NIC')
        if key=='net0' and options.get('link_down')!='1': raise Error('Service NIC must stay disconnected')
        if key=='net1' and options.get('link_down')=='1': raise Error('WAN NIC must be connected')
        if mac.upper() in macs: raise Error('Duplicate planned NIC MAC')
        macs.add(mac.upper())
    if str(plan.get('protection'))!=str(original.get('protection','0')):
        raise Error('Saved protection differs from original')
    volume=plan.get('volume')
    if volume is not None:
        if not isinstance(volume,str) or ':' not in volume or any(c in volume for c in (',','\n','\r')):
            raise Error('Invalid imported volume')
        old={value.split(',')[0] for value in disk_values(original).values()}
        if volume in old: raise Error('Imported volume is an original disk')
    return plan

def verify_old_disks(before,after):
    for key,value in disk_values(before).items():
        if after.get(key)!=value: raise Error('Original disk configuration changed: '+key)

def verify_applied(state,cfg):
    verify_old_disks(state['original_config'],cfg)
    if str(cfg.get('protection','0'))!=state['protection']: raise Error('VM protection changed')
    expected=dict(state['new_config']); expected[state['ide_slot']]=state['volume']
    for key,value in expected.items():
        actual=str(cfg.get(key,''))
        if key.startswith('net'):
            model,mac,options=parse_network(actual)
            wanted_model,wanted_mac,wanted_options=parse_network(value)
            ok=(model==wanted_model and mac.upper()==wanted_mac.upper() and options==wanted_options)
        elif DISK.fullmatch(key):
            ok=actual.split(',')[0]==str(value).split(',')[0]
        else:
            ok=actual==str(value)
        if not ok: raise Error('Applied configuration differs: '+key)
    if {key for key in cfg if re.fullmatch(r'net\d+',key)}!={'net0','net1','net2','net3'}:
        raise Error('Unexpected adapter count')

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def atomic_json(path,data):
    path=Path(path); path.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if path.parent.is_symlink() or path.is_symlink(): raise Error('State path is a symlink')
    os.chmod(path.parent,0o700)
    fd,temp=tempfile.mkstemp(prefix='.state-',dir=str(path.parent))
    try:
        os.chmod(temp,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as stream:
            json.dump(data,stream,ensure_ascii=False,indent=2,sort_keys=True)
            stream.write('\n'); stream.flush(); os.fsync(stream.fileno())
        os.replace(temp,path)
        if os.name=='posix':
            d=os.open(str(path.parent),os.O_RDONLY)
            try: os.fsync(d)
            finally: os.close(d)
    finally:
        if os.path.exists(temp): os.unlink(temp)

def image_info(runner,path,expected_sha=None):
    path=Path(path)
    if not path.is_file() or path.is_symlink() or path.stat().st_size>MAX_IMAGE:
        raise Error('Invalid image file or size')
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda:stream.read(1024*1024),b''): digest.update(chunk)
    actual=digest.hexdigest()
    if expected_sha and actual!=expected_sha.lower(): raise Error('Image SHA-256 differs')
    data=json.loads(runner('qemu-img','info','--output=json',str(path)))
    if data.get('format')!='qcow2' or data.get('backing-filename'):
        raise Error('Expected standalone QCOW2 without a backing file')
    if not 0<int(data.get('virtual-size',0))<=128*1024**3: raise Error('Invalid virtual image size')
    check=json.loads(runner('qemu-img','check','--output=json',str(path),timeout=600))
    if check.get('corruptions',0) or check.get('check-errors',0): raise Error('qemu-img found image errors')
    data['sha256']=actual
    return data

def download_image(url,destination,expected_sha=None):
    destination=Path(destination); destination.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
    if destination.exists(): return destination
    parsed=urlparse(url); expected_size=None; actual_url=url
    try:
        if parsed.hostname in ('disk.yandex.ru','disk.yandex.com'):
            match=re.fullmatch(r'/d/([^/]+)(/.*)?',parsed.path)
            if not match: raise Error('Expected a public Yandex Disk file URL')
            api='https://cloud-api.yandex.net/v1/disk/public/resources?'+urlencode({
                'public_key':f'https://{parsed.hostname}/d/{match[1]}','path':unquote(match[2] or '/')})
            with urlopen(api,timeout=30) as response: meta=json.load(response)
            if meta.get('type')!='file' or not meta.get('file'): raise Error('URL is not a public file')
            expected_size=int(meta.get('size',0))
            if not 0<expected_size<=MAX_IMAGE: raise Error('Invalid public image size')
            if expected_sha and meta.get('sha256','').lower()!=expected_sha.lower():
                raise Error('Public image SHA-256 changed; review the image first')
            actual_url=meta['file']  # Signed URL never enters logs/state.
        elif parsed.scheme!='https' or parsed.query or parsed.fragment:
            raise Error('Custom URL must be plain HTTPS')
        fd,temp=tempfile.mkstemp(prefix='.image-',dir=str(destination.parent))
        try:
            size=0; digest=hashlib.sha256()
            with os.fdopen(fd,'wb') as stream,urlopen(actual_url,timeout=60) as response:
                while True:
                    chunk=response.read(1024*1024)
                    if not chunk: break
                    size+=len(chunk)
                    if size>MAX_IMAGE: raise Error('Downloaded image exceeds limit')
                    digest.update(chunk); stream.write(chunk)
                stream.flush(); os.fsync(stream.fileno())
            if expected_size is not None and size!=expected_size: raise Error('Downloaded size differs')
            if expected_sha and digest.hexdigest()!=expected_sha.lower(): raise Error('Downloaded SHA-256 differs')
            os.chmod(temp,0o600); os.replace(temp,destination)
        finally:
            if os.path.exists(temp): os.unlink(temp)
    except (HTTPError,URLError,TimeoutError,OSError) as error:
        raise Error('Image download failed: '+type(error).__name__) from None
    return destination

class Migrator:
    def __init__(self,runner=None,work=Path('/root/proxmox-isp-ecorouter'),
                 config_dir=Path('/etc/pve/qemu-server'),node=None,firewall_dir=Path('/etc/pve/firewall')):
        self.run=runner or Runner(); self.work=Path(work); self.config_dir=Path(config_dir)
        self.node=node or socket.gethostname().split('.')[0]
        self.firewall_dir=Path(firewall_dir)
    def config(self,vmid): return parse_config(self.run('qm','config',str(vmid)))
    def status(self,vmid):
        match=re.fullmatch(r'status:\s*(\w+)',self.run('qm','status',str(vmid)).strip())
        if not match: raise Error('Unexpected VM status')
        return match[1]
    def get_json(self,path): return json.loads(self.run('pvesh','get',path,'--output-format','json'))
    def pending(self,vmid):
        return self.get_json(f'/nodes/{self.node}/qemu/{vmid}/pending')
    def existing_macs(self,exclude_vmid=None):
        files=(Path('/etc/pve/nodes').glob('*/qemu-server/*.conf')
               if self.config_dir==Path('/etc/pve/qemu-server') else self.config_dir.glob('*.conf'))
        owners={}
        for file in files:
            if not file.stem.isdigit() or int(file.stem)==exclude_vmid: continue
            for line in file.read_text(encoding='utf-8').splitlines():
                match=re.match(r'^net[0-9]+:\s*[^=,]+=([0-9A-Fa-f:]{17})(?:,|$)',line)
                if match: owners.setdefault(match[1].upper(),set()).add(int(file.stem))
        for file in self.work.glob('[0-9]*/state.json'):
            data=json.loads(file.read_text(encoding='utf-8'))
            vmid=int(data['vmid'])
            if vmid==exclude_vmid: continue
            for key,value in data.get('new_config',{}).items():
                if re.fullmatch(r'net[0-9]+',key):
                    owners.setdefault(parse_network(value)[1].upper(),set()).add(vmid)
        return owners
    def reserve_macs(self):
        MAC_RESERVATIONS.update(self.existing_macs())
        return MAC_RESERVATIONS
    def check_new_macs(self,state):
        occupied=self.existing_macs(exclude_vmid=state['vmid'])
        for key,value in state['new_config'].items():
            if re.fullmatch(r'net[0-9]+',key) and parse_network(value)[1].upper() in occupied:
                raise Error('Planned MAC is already reserved by another VM')
    def check_firewall(self,plan):
        remap=plan['source_networks']!={'wan':'net1','hq':'net2','br':'net3'}
        path=self.firewall_dir/(str(plan['vmid'])+'.fw')
        if not remap or not path.exists(): return
        section=''
        for line in path.read_text(encoding='utf-8').splitlines():
            line=line.strip()
            if not line or line.startswith('#'): continue
            if line.startswith('['):
                section=line.upper()
                if re.match(r'\[IPSET\s+IPFILTER-NET[0-9]+\]',section):
                    raise Error('NIC remapping with per-interface firewall IP sets requires manual review')
            elif section=='[RULES]':
                raise Error('NIC remapping with custom VM firewall rules requires manual review')
    def check_services(self,vmid):
        if any('pending' in item or int(item.get('delete',0))!=0 for item in self.pending(vmid)):
            raise Error('VM has pending configuration changes')
        for item in self.get_json('/cluster/ha/resources'):
            if item.get('sid')=='vm:'+str(vmid): raise Error('Target belongs to HA')
        for item in self.get_json('/cluster/replication'):
            if str(item.get('guest',''))==str(vmid) or str(item.get('id','')).startswith(str(vmid)+'-'):
                raise Error('Target belongs to a replication job')
    def storage(self,cfg,name=None):
        if not name:
            boot=effective_original_boot(cfg)[6:].split(';')[0].split(',')[0]
            value=cfg.get(boot,'')
            if ':' not in value: raise Error('Cannot infer storage; specify --storage')
            name=value.split(':',1)[0]
        if not re.fullmatch(r'[A-Za-z0-9_.-]+',name): raise Error('Invalid storage ID')
        definition=self.get_json('/storage/'+name)
        status=self.get_json(f'/nodes/{self.node}/storage/{name}/status')
        content=definition.get('content','')
        if isinstance(content,str): content=content.split(',')
        if 'images' not in content or not status.get('active') or status.get('enabled',1)==0:
            raise Error('Storage is not active/enabled for images')
        kind=definition.get('type',status.get('type'))
        if kind not in ('dir','lvmthin','zfspool'): raise Error('Unsupported storage type: '+str(kind))
        return {'storage':name,'type':kind,'avail':int(status.get('avail',0))}
    def supported_machine(self):
        lines=self.run('kvm','-machine','help').splitlines()
        if any(re.match(r'^pc-i440fx-7\.0\s',line) for line in lines): return 'pc-i440fx-7.0'
        if any(re.match(r'^pc\s',line) and 'i440' in line.lower() for line in lines): return 'pc'
        raise Error('No supported i440fx machine found')
    def preflight(self,vmid,storage=None,override=None,machine=None):
        self.check_services(vmid); cfg=self.config(vmid)
        plan=build_plan(vmid,cfg,self.status(vmid),self.storage(cfg,storage),
            override=override,machine=machine or self.supported_machine())
        self.check_firewall(plan)
        return plan
    def state_path(self,vmid): return self.work/str(vmid)/'state.json'
    def load(self,vmid):
        path=self.state_path(vmid)
        if path.is_symlink(): raise Error('State file is a symlink')
        if not path.exists(): return None
        data=json.loads(path.read_text(encoding='utf-8'))
        if data.get('version')!=1 or data.get('vmid')!=int(vmid): raise Error('Unexpected state version/VMID')
        if data.get('stage') not in ('prepared','importing','imported','applying','complete','rolling_back','rolled_back'):
            raise Error('Unknown saved operation stage')
        return data
    def save(self,state,stage=None):
        if stage: state['stage']=stage
        state['updated_at']=now(); atomic_json(self.state_path(state['vmid']),state)
    def stop(self,vmid):
        if self.status(vmid)=='stopped': return
        try: self.run('qm','shutdown',str(vmid),'--timeout','120',timeout=150)
        except (Error,subprocess.TimeoutExpired):
            if self.status(vmid)!='stopped': raise Error('VM did not shut down. Stop it manually and rerun; no forced stop issued') from None
        if self.status(vmid)!='stopped': raise Error('VM is still running')
    def backup(self,plan):
        folder=self.work/str(plan['vmid']); folder.mkdir(mode=0o700,parents=True,exist_ok=True)
        if folder.is_symlink(): raise Error('Backup folder is a symlink')
        os.chmod(folder,0o700)
        raw=self.config_dir/(str(plan['vmid'])+'.conf')
        if not raw.is_file(): raise Error('Local raw VM config not found')
        target=folder/'original.conf'
        if target.exists(): raise Error('Backup exists without matching state; manual review required')
        with target.open('xb') as out:
            os.chmod(target,0o600); out.write(raw.read_bytes()); out.flush(); os.fsync(out.fileno())
        atomic_json(folder/'original-current.json',plan['original_config'])
    def recover_import(self,state):
        current=self.config(state['vmid']); before=state['import_before']
        added={k:v for k,v in current.items() if re.fullmatch(r'unused\d+',k) and k not in before}
        if len(added)!=1:
            raise Error('Import outcome unknown: expected one new unused disk. Inspect config/storage; import will not be repeated')
        key,value=next(iter(added.items())); expected=dict(before); expected[key]=value
        if fingerprint(current)!=fingerprint(expected): raise Error('Config changed during import; manual review required')
        volume=value.split(',')[0]
        if not volume.startswith(state['storage']['storage']+':'): raise Error('Imported storage differs')
        state['volume']=volume; state['unused_key']=key; state['pre_apply_config']=current
        validate_mutation_plan(state,state['vmid'])
        self.save(state,'imported'); return state
    def check_identity(self,vmid,state):
        validate_mutation_plan(state,vmid)
        current=self.config(vmid)
        name=current.get('name','')
        if not is_isp_name(name) or name!=state['original_config']['name']:
            raise Error('Current VM identity is not the original ISP')
        return current
    def guarded_set(self,vmid,state,updates,delete=None):
        current=self.check_identity(vmid,state)
        delete=list(delete or [])
        allowed=RESTORABLE|{state['ide_slot']}
        if not set(updates)<=allowed or any(key not in RESTORABLE for key in delete):
            raise Error('Unsafe VM configuration mutation')
        if any(DISK.fullmatch(key) or key in ('protection','delete') for key in delete):
            raise Error('Disk/protection removal is forbidden')
        for key,value in updates.items():
            if str(value).startswith('-'): raise Error('Unsafe VM option value')
            if DISK.fullmatch(key):
                if key!=state['ide_slot'] or key in state['original_config'] or key in current:
                    raise Error('Existing disk slot modification is forbidden')
                if value!=state.get('volume'): raise Error('Imported disk identity differs')
                unused=state.get('unused_key')
                if not unused or current.get(unused,'').split(',')[0]!=value:
                    raise Error('Imported unused disk was not found')
        args=[]
        for key,value in updates.items(): args+=['--'+key,str(value)]
        if delete: args+=['--delete',','.join(delete)]
        return self.run('qm','set',str(vmid),*args,timeout=180)
    def apply(self,plan,image_path,image_data):
        validate_mutation_plan(plan)
        vmid=plan['vmid']; state=self.load(vmid)
        self.check_identity(vmid,state or plan)
        if state is None:
            if fingerprint(self.config(vmid))!=plan['before_fingerprint']: raise Error('Config changed since plan')
            self.backup(plan)
            state=dict(plan,version=1,stage='prepared',created_at=now(),image={
                'path':str(image_path),'sha256':image_data.get('sha256'),
                'format':image_data['format'],'virtual_size':int(image_data['virtual-size'])})
            self.save(state)
        if state['stage']=='complete':
            verify_applied(state,self.config(vmid)); print(f'{vmid}: already migrated; no changes'); return state
        if state['stage'] in ('rolled_back','rolling_back'): raise Error('Migration rolled back; review state before another migration')
        saved_image=state['image']
        if (saved_image.get('sha256')!=image_data.get('sha256') or
                saved_image['format']!=image_data['format'] or
                int(saved_image['virtual_size'])!=int(image_data['virtual-size'])):
            raise Error('Resume image differs from the saved migration image')
        self.check_services(vmid)
        self.check_new_macs(state)
        self.check_firewall(state)
        if state['stage']=='prepared':
            if fingerprint(self.config(vmid))!=state['before_fingerprint']: raise Error('Config drift before migration')
            fresh_storage=self.storage(state['original_config'],state['storage']['storage'])
            if fresh_storage['type']!=state['storage']['type']: raise Error('Storage type changed since plan')
            if int(fresh_storage.get('avail',0))<int(image_data['virtual-size'])+64*1024**2:
                raise Error('Insufficient storage for imported virtual disk')
            self.stop(vmid); current=self.config(vmid)
            if fingerprint(current)!=state['before_fingerprint']: raise Error('Config changed during shutdown')
            state['import_before']=current; self.save(state,'importing')
            fmt='qcow2' if state['storage']['type']=='dir' else 'raw'
            try: self.run('qm','importdisk',str(vmid),str(image_path),state['storage']['storage'],'--format',fmt,timeout=7200)
            except (Error,subprocess.TimeoutExpired):
                self.recover_import(state)
                raise Error('Import reported failure but disk was found. Rerun to resume safely') from None
            self.recover_import(state)
        elif state['stage']=='importing': self.recover_import(state)
        if state['stage']=='imported':
            self.stop(vmid)
            if fingerprint(self.config(vmid))!=fingerprint(state['pre_apply_config']): raise Error('Config drift after import')
            updates=dict(state['new_config']); updates[state['ide_slot']]=state['volume']
            state['applied_config']=updates; self.save(state,'applying')
            args=[]
            for key,value in updates.items(): args+=['--'+key,str(value)]
            try: self.guarded_set(vmid,state,updates)
            except (Error,subprocess.TimeoutExpired):
                try: verify_applied(state,self.config(vmid))
                except Error: raise Error('Config update incomplete; old disks/protection retained. Inspect config or use --rollback') from None
        if state['stage']=='applying':
            verify_applied(state,self.config(vmid))
            if self.status(vmid)!='stopped': raise Error('VM unexpectedly started')
            state['post_fingerprint']=fingerprint(self.config(vmid)); self.save(state,'complete')
            print(f'{vmid}: migrated; VM stopped. Configure EcoRouter through its console.')
        return state
    def rollback(self,vmid):
        state=self.load(vmid)
        if not state: raise Error('No state for rollback')
        self.check_identity(vmid,state)
        if state['stage']=='rolled_back':
            current=self.config(vmid); verify_old_disks(state['original_config'],current)
            if current.get('boot')!=state['original_effective_boot']: raise Error('Boot changed after rollback')
            if str(current.get('protection','0'))!=state['protection']: raise Error('Protection changed after rollback')
            return state
        self.check_services(vmid); current=self.config(vmid)
        verify_old_disks(state['original_config'],current)
        if str(current.get('protection','0'))!=state['protection']: raise Error('Protection changed; rollback aborted')
        if state['stage']=='complete' and fingerprint(current)!=state['post_fingerprint']:
            raise Error('Config drift after migration; automatic rollback aborted')
        self.stop(vmid)
        updates={key:state['original_config'][key] for key in RESTORABLE if key in state['original_config']}
        updates['boot']=state['original_effective_boot']
        delete=sorted(key for key in state['new_config'] if key not in state['original_config'] and key!='boot')
        if any(key not in RESTORABLE for key in delete): raise Error('Non-restorable deletion requested')
        self.save(state,'rolling_back'); args=[]
        for key,value in updates.items(): args+=['--'+key,str(value)]
        if delete: args+=['--delete',','.join(delete)]
        try: self.guarded_set(vmid,state,updates,delete)
        except (Error,subprocess.TimeoutExpired): raise Error('Rollback failed; inspect config and rerun --rollback') from None
        current=self.config(vmid); verify_old_disks(state['original_config'],current)
        if str(current.get('protection','0'))!=state['protection']: raise Error('Protection changed during rollback')
        for key,value in updates.items():
            if current.get(key)!=value: raise Error('Rollback differs: '+key)
        if any(key in current for key in delete): raise Error('Rollback left new fields')
        self.save(state,'rolled_back'); print(f'{vmid}: old boot restored; old and new disks retained; VM stopped.'); return state

def parse_vmids(value):
    try: ids=sorted(set(int(item.strip()) for item in value.split(',')))
    except ValueError: raise argparse.ArgumentTypeError('Use comma-separated VMIDs') from None
    if not ids or any(not 100<=i<=999999999 for i in ids): raise argparse.ArgumentTypeError('VMIDs must be 100..999999999')
    return ids

def show_plan(plan):
    print(f"VM {plan['vmid']} ({plan['original_config']['name']}), status={plan['original_status']}, protection={plan['protection']}")
    print('  Preserve all old disks; new slot '+plan['ide_slot']+'; storage '+plan['storage']['storage'])
    print('  4096 MiB RAM, 2 CPU cores, machine='+plan['new_config']['machine'])
    print('  Original mapping: '+json.dumps(plan['source_networks'],sort_keys=True))
    for key in ('net0','net1','net2','net3'): print('  '+key+': '+plan['new_config'][key])

def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__,formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--vmids',type=parse_vmids,help='Explicit comma-separated ISP VMIDs')
    action=parser.add_mutually_exclusive_group()
    action.add_argument('--apply',action='store_true',help='Apply/resume migration; VMs remain stopped')
    action.add_argument('--rollback',action='store_true',help='Restore old boot/config retaining all disks')
    parser.add_argument('--yes',action='store_true',help='Explicitly skip interactive operation phrase')
    parser.add_argument('--storage',help='Target storage; default original boot-disk storage')
    image=parser.add_mutually_exclusive_group()
    image.add_argument('--image',type=Path,help='Local standalone QCOW2')
    image.add_argument('--image-url',default=DEFAULT_URL,help='Public image URL')
    parser.add_argument('--sha256',help='Expected SHA-256; required for custom URL')
    parser.add_argument('--work',type=Path,default=Path('/root/proxmox-isp-ecorouter'))
    parser.add_argument('--node',help='Local Proxmox node name')
    for role in ('wan','hq','br'): parser.add_argument('--'+role+'-net',help='Explicit original adapter, e.g. net0')
    args=parser.parse_args(argv)
    if os.name!='posix' or not hasattr(os,'geteuid') or os.geteuid()!=0: raise Error('Run as root on the Proxmox node owning the VMs')
    for command in ('qm','pvesh','qemu-img','kvm'):
        if not shutil.which(command): raise Error('Required command missing: '+command)
    migration=Migrator(work=args.work,node=args.node); migration.reserve_macs(); ids=args.vmids
    if not ids:
        rows=migration.get_json(f'/nodes/{migration.node}/qemu')
        candidates=[row for row in rows if is_isp_name(row.get('name',''))]
        if not candidates: raise Error('No local ISP-named VMs found')
        print('Local ISP candidates; none selected automatically:')
        for row in sorted(candidates,key=lambda r:int(r['vmid'])): print(f"  {row['vmid']}  {row.get('name')}  {row.get('status','')}")
        if not sys.stdin.isatty(): raise Error('Specify --vmids with non-interactive stdin')
        ids=parse_vmids(input('Enter comma-separated target VMIDs: '))
        if not set(ids)<={int(row['vmid']) for row in candidates}: raise Error('VMID is not in candidate list')
    override={role:getattr(args,role+'_net') for role in ('wan','hq','br') if getattr(args,role+'_net') is not None} or None
    plans=[]
    for vmid in ids:
        saved=migration.load(vmid)
        if saved and (args.apply or args.rollback):
            plan=saved; print(f"VM {vmid}: saved stage={saved['stage']}")
        else:
            plan=migration.preflight(vmid,args.storage,override); show_plan(plan)
        plans.append(plan)
    if not args.apply and not args.rollback:
        print('Plan only. Use --apply to migrate or --rollback to restore old boot/config.'); return 0
    phrase=('ROLLBACK ' if args.rollback else 'MIGRATE ')+','.join(map(str,ids))
    if not args.yes:
        if not sys.stdin.isatty(): raise Error('Interactive confirmation required; use --yes explicitly for automation')
        if input('Type exactly '+phrase+' to continue: ')!=phrase: raise Error('Not confirmed')
    import fcntl
    args.work.mkdir(mode=0o700,parents=True,exist_ok=True)
    if args.work.is_symlink(): raise Error('Work directory is a symlink')
    os.chmod(args.work,0o700)
    with (args.work/'run.lock').open('a') as lock:
        os.chmod(args.work/'run.lock',0o600)
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise Error('Another migration is running') from None
        if args.rollback:
            for vmid in ids: migration.rollback(vmid)
            return 0
        expected=args.sha256
        if not args.image and args.image_url==DEFAULT_URL: expected=expected or DEFAULT_SHA256
        elif not args.image and not expected: raise Error('--sha256 required for custom URL')
        if expected and not re.fullmatch('[0-9A-Fa-f]{64}',expected): raise Error('Invalid SHA-256')
        pending=[]
        for plan in plans:
            saved=migration.load(plan['vmid'])
            if saved and saved['stage']=='complete':
                verify_applied(saved,migration.config(plan['vmid'])); print(f"{plan['vmid']}: already migrated; no changes")
            else: pending.append(plan)
        if not pending: return 0
        image_path=args.image or download_image(args.image_url,args.work/'EcoRouter.qcow2',expected)
        info=image_info(migration.run,image_path,expected)
        for plan in pending: migration.apply(plan,image_path,info)
    return 0

if __name__=='__main__':
    try: sys.exit(main())
    except (Error,argparse.ArgumentTypeError,subprocess.TimeoutExpired,ValueError,OSError) as error:
        print('ERROR: '+redact(error),file=sys.stderr); sys.exit(1)
