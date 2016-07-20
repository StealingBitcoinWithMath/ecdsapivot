#!/usr/bin/env python
# vim: sw=4 ts=4 et ai si bg=dark

import sys
import time
import pylru
import signal
import logging
import itertools
import traceback

from pprint import pprint
from binascii import hexlify, unhexlify
from collections import deque
from bitcoinrpc.authproxy import AuthServiceProxy
from pybitcointools import *

try:
    txhash
except:
    txhash = tx_hash

txcount = 0
cachemiss = 0
cachehit = 0

def print_stderr(s):
    # escape characters to clear the rest of the line
    sys.stderr.write('\033[0G%s\033[0K\n' % s)

def asp_from_config(filename):
    rpcport = '8332'
    rpcconn = '127.0.0.1'
    rpcuser = None
    rpcpass = None
    with open(filename, 'r') as f:
        for line in f:
            (key, val) = line.rstrip().replace(' ', '').split('=')
            if key == 'rpcuser':
                rpcuser = val
            elif key == 'rpcpassword':
                rpcpass = val
            elif key == 'rpcport':
                rpcport = val
            elif key == 'rpcconnect':
                rpcconn = val
        f.close()
    if rpcuser is not None and rpcpass is not None:
        rpcurl = 'http://%s:%s@%s:%s' % (rpcuser, rpcpass, rpcconn, rpcport)
        #print_stderr('RPC server: %s' % rpcurl)
        return AuthServiceProxy(rpcurl)
n
configfile = sys.argv[1]
rpc = asp_from_config(configfile)

def reconnect_rpc():
    rpc = asp_from_config(configfile)

def getrawtx(txid):
    retries = 3
    e = None
    while retries > 0:
        try:
            tx = rpc.getrawtransaction(txid, 1)
            return tx
        except e:
            pass
        time.sleep(1)
        print 'attempting to reconnect' 
        reconnect_rpc()
        retries -= 1
    print_stderr('getrawtx failed')
    raise e

def solve_dupe_r(r,pub,s1,s2,z1,z2):
    r = int(r,16)
    s1 = int(s1,16)
    s2 = int(s2,16)
    z1 = int(z1,16)
    z2 = int(z2,16)

    k_candidates = []
    k_candidates.append( ((z1 - z2) * inv( s1 -s2, N)) % N )
    k_candidates.append( ((z1 - z2) * inv( s1 -s2, N)) % N )
    k_candidates.append( ((z1 - z2) * inv(-s1 -s2, N)) % N )
    k_candidates.append( ((z1 - z2) * inv( s1 -s2, N)) % N )
    for k in k_candidates:
        priv = solve_for_priv(r, s1, z1, k)
        t = privkey_to_pubkey(priv)
        if pub == encode_pubkey(t, 'hex'):
            return (k, priv)
        if pub == encode_pubkey(t, 'hex_compressed'):
            return (k, priv)
        
    return None

def solve_for_k(r, s, z, priv):
    k = ((r * priv + z) * inv(s, N)) % N
    return k

def solve_for_priv(r, s, z, k):
    priv = ((s * k - z) * inv(r, N)) % N
    return priv

def dump_tx_ecdsa(txid, i):
    try:
        tx = getrawtx(txid)
    except:
        print_stderr('getrawtx failed: ' + txid)
        raise

    vin = tx['vin'][i]
    if 'coinbase' in vin:
        return

    prev_tx = getrawtx(vin['txid'])
    prev_vout = prev_tx['vout'][vin['vout']]
    prev_type = prev_vout['scriptPubKey']['type'] 
    script = prev_vout['scriptPubKey']['hex']

    if prev_type == 'pubkeyhash':
        sig, pub = vin['scriptSig']['asm'].split(' ')
    elif prev_type == 'pubkey':
        sig = vin['scriptSig']['asm']
        pub, _ = prev_vout['scriptPubKey']['asm'].split(' ')
    else:
        print_stderr("%6d %s %4d ERROR_UNHANDLED_SCRIPT_TYPE" % (txid, i))
        raise

    x = pub[2:66]

    #print sig
    if sig[-1] == ']':
        sig, hashcode_txt = sig.strip(']').split('[')
        if hashcode_txt == 'ALL':
            hashcode = 1
        elif hashcode_txt == 'SINGLE':
            hashcode = 3
        else:
            print hashcode_txt
            print_stderr("%6d %s %4d ERROR_UNHANDLED_HASHCODE" % (height, txid, hashcode_txt))
            raise
    else:
        hashcode = int(sig[-2:], 16)
        sig = sig[:-2]

    modtx = serialize(signature_form(deserialize(tx['hex']), i, script, hashcode))
    z = hexlify(txhash(modtx, hashcode))

    _, r, s = der_decode_sig(sig)
    r = encode(r, 16, 64)
    s = encode(s, 16, 64)

    #print verify_tx_input(tx['hex'], i, script, sig, pub)
    return {'txid':txid,'i':i,'x':x,'r':r,'s':s,'z':z,'pub':pub}

vins = []

args = sys.argv[2:]
for x in xrange(0, len(args), 2):
    txid = args[x]
    n = int(args[x+1])
    vins.append(dump_tx_ecdsa(txid, n))

privs = {}
dupes_all = []
dupes_r = {}
dupes_x = {}

with open('rrr.dupe','rb') as f:
    for line in f:
        line = line.strip()
        height, txid, i, r, x, ysign = line.split(' ')

        i = int(i)
        ysign = int(ysign)
        height = int(height)

        data = {'txid':txid,'i':i,'r':r,'x':x}
        if r not in dupes_r:
            dupes_r[r] = []
        if x not in dupes_x:
            dupes_x[x] = []
        dupes_all.append(data)
        dupes_r[r].append(data)
        dupes_x[x].append(data)

for r, dupes in dupes_r.iteritems():
    if len(dupes) > 1:
        for d1, d2 in itertools.combinations(dupes, 2):
            if d1['x'] == d2['x']:
                try:
                    tx1 = dump_tx_ecdsa(d1['txid'], d1['i'])
                    tx2 = dump_tx_ecdsa(d2['txid'], d2['i'])
                    solved = solve_dupe_r(tx1['r'], tx1['pub'], tx1['s'], tx2['s'], tx1['z'], tx2['z'])
                    if solved is not None:
                        k = solved[0]
                        priv = solved[1]
                        privs[d1['r']] = k
                        privs[d1['x']] = priv
                        print encode_privkey(k, 'hex')    + ':' + d1['r'] + ':r:1'
                        print encode_privkey(priv, 'hex') + ':' + d1['x'] + ':x:1'
                        break
                except KeyboardInterrupt:
                    raise
                except:
                    traceback.print_exc()

passes = 1
looping = True

while looping:
    passes += 1
    looping = False

    for r, dupes in dupes_r.iteritems():
        if r in privs:
            k = privs[r]
            for d in dupes:
                if d['x'] not in privs:
                    try:
                        tx = dump_tx_ecdsa(d['txid'], d['i'])
                        priv = solve_for_priv(int(tx['r'],16), int(tx['s'],16), int(tx['z'],16), k)
                        t = privkey_to_pubkey(priv)
                        if tx['pub'] == encode_pubkey(t, 'hex') or tx['pub'] == encode_pubkey(t, 'hex_compressed'):
                            privs[d['x']] = priv
                            print encode_privkey(priv, 'hex') + ':' + d['x'] + ':x:' + str(passes)
                            looping = True
                            #print tx['pub']
                    except KeyboardInterrupt:
                        raise
                    except:
                        traceback.print_exc()

    for x, dupes in dupes_x.iteritems():
        if x in privs:
            priv = privs[x]
            for d in dupes:
                if d['r'] not in privs:
                    try:
                        tx = dump_tx_ecdsa(d['txid'], d['i'])
                        k = solve_for_k(int(tx['r'],16), int(tx['s'],16), int(tx['z'],16), priv)
                        privs[d['r']] = k
                        print encode_privkey(k, 'hex') + ':' + d['r'] + ':r:' + str(passes)
                        looping = True
                        #print tx['pub']
                    except KeyboardInterrupt:
                        raise
                    except:
                        traceback.print_exc()
