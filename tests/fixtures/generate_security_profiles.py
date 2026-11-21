"""Generate public synthetic RSN-PSK vectors using Python stdlib crypto.

Run here, then copy security-profiles.txt unchanged to the companion fixture directory.
The password is synthetic-test-password. These are not on-air captures.
"""
from pathlib import Path
import hashlib
import hmac
import struct

# Synthetic interoperable corpus. Password/addresses/SSID are deliberately public.
AP, STA, SSID = bytes.fromhex('020000000001'), bytes.fromhex('020000000002'), b'cipher-test-lab'
PASSWORD = b'synthetic-test-password'
ANONCE, SNONCE = bytes([0x11])*32, bytes([0x22])*32
pmk = hashlib.pbkdf2_hmac('sha1', PASSWORD, SSID, 4096, 32)
prf = b'Pairwise key expansion\0' + b''.join(sorted([AP,STA])) + b''.join(sorted([ANONCE,SNONCE])) + b'\0'
kck = hmac.new(pmk, prf, hashlib.sha1).digest()[:16]
def header(fc, a1, a2, a3): return struct.pack('<HH',fc,0)+a1+a2+a3+b'\0\0'
beacon = header(0x80,b'\xff'*6,AP,AP)+b'\0'*12+bytes([0,len(SSID)])+SSID
def eapol(msg, pair, group, version=None, pmf=0):
    version = version or (1 if pair==2 else 2)
    rsn = bytes([48,20,1,0,0,15,172,group,1,0,0,15,172,pair,1,0,0,15,172,2,pmf,0]) if msg==2 else b''
    e=bytearray(99+len(rsn)); e[0:5]=bytes([2,3,0,95+len(rsn),2])
    flags={1:0x88,2:0x108,3:0x13c8,4:0x308}[msg]|version
    e[5:7]=struct.pack('>H',flags)
    e[7:9]=struct.pack('>H', (32 if pair==2 else 16) if msg in (1,3) else 0)
    e[9:17]=struct.pack('>Q',7 if msg<3 else 8)
    if msg!=4:e[17:49]=SNONCE if msg==2 else ANONCE
    e[97:99]=struct.pack('>H',len(rsn));e[99:]=rsn
    if msg!=1:e[81:97]=hmac.new(kck,e,hashlib.md5 if version==1 else hashlib.sha1).digest()[:16]
    return e
def frame(msg,e):
    return header(0x208 if msg in (1,3) else 0x108,STA if msg in(1,3) else AP,AP if msg in(1,3) else STA,AP)+bytes.fromhex('aaaa03000000888e')+e
cases=[]
def add(name, frames, pair=0,group=0,ver=0,state='no_usable_pair', hashline=None):
    cases.append((name,frames,pair,group,ver,state,hashline))
for pair,group in [(2,2),(4,2),(4,4),(8,2),(8,4),(8,8)]:
    version=1 if pair==2 else 2
    for peer in (1,3):
        m2=eapol(2,pair,group)
        zero=bytearray(m2);zero[81:97]=b'\0'*16
        expected=f'WPA*02*{m2[81:97].hex()}*{AP.hex()}*{STA.hex()}*{SSID.hex()}*{ANONCE.hex()}*{zero.hex()}*{0 if peer==1 else 2:02x}'
        frames=[(0,beacon),(1000 if peer==1 else 3000,frame(peer,eapol(peer,pair,group))),(2000,frame(2,m2))]
        add(f'p{pair}_g{group}_m{peer}m2',frames,pair,group,version,'structural_only',expected)
for version in (1,2,3):
    for pair,group in [(2,2),(4,4),(8,8)]:
        if version==(1 if pair==2 else 2):continue
        add(f'wrong_version_p{pair}_v{version}',[(0,beacon),(1000,frame(1,eapol(1,pair,group,version))),(2000,frame(2,eapol(2,pair,group,version)))])
for peer in (1,3):
    for pair,group in [(2,2),(4,4),(8,8)]:
        other=2 if pair==2 else 1
        otherpair=4 if other==2 else 2
        add(f'cross_version_p{pair}_peer{peer}',[(0,beacon),(1000 if peer==1 else 3000,frame(peer,eapol(peer,otherpair,otherpair))),(2000,frame(2,eapol(2,pair,group)))])
for second_pair,second_group in [(8,4),(4,2)]:
    add(f'conflicting_p{second_pair}_g{second_group}',[(0,beacon),(1000,frame(1,eapol(1,4,4))),(2000,frame(2,eapol(2,4,4))),(2100,frame(2,eapol(2,second_pair,second_group)))],state='ambiguous_security_profile')
for label,offset,value in [('sae',118,8),('enterprise',118,1),('sha256',118,6),('vendor_group',103,1),('vendor_pair',109,1),('wpa1',4,254),('unknown_pair',112,255),('pmf_invalid',119,64),('bad_version',101,2)]:
    e=eapol(2,8,8);e[offset]=value
    add(label,[(0,beacon),(1000,frame(1,eapol(1,8,8))),(2000,frame(2,e))])
for pair,group in [(2,4),(2,8),(4,8)]:
    add(f'deferred_p{pair}_g{group}',[(0,beacon),(1000,frame(1,eapol(1,pair,group))),(2000,frame(2,eapol(2,pair,group)))])
lines=['# Synthetic RSN-PSK fixtures; password synthetic-test-password; no captured user traffic.']
for name,frames,pair,group,ver,state,hashline in cases:
    lines.append(f'CASE {name} {pair} {group} {ver} {state}')
    lines += [f'FRAME {t} 1 {f.hex()}' for t,f in frames]
    if hashline:lines.append(f'HASH {hashline}')
    lines.append('END')
text='\n'.join(lines)+'\n'
Path(__file__).with_name('security-profiles.txt').write_text(text, encoding='utf-8', newline='\n')
print(f'{len(cases)} cases; SHA256 {hashlib.sha256(text.encode()).hexdigest()}')
