#!/usr/bin/env python
# -*- coding: utf-8 -*-

from nsp import NSPClient
import time
from hashlib import md5
from urllib import quote_plus

def sendMsg():
    nsp = NSPClient('2', '8e68aa485d4c2a3853e1fd9dd278847d')
    svc = nsp.service('nsp.event')
    message_type = 'nsp.cloudprint'
    uid = 1130703
    cid = '00d41d8cd98f00b204e980091546ffe6'
    files = list()
    '''
    name = '小说.txt'
    f0 = {'name' : name, 'size' : '3265', 'md5' : 'd0ee66c260ae39fb1efb4f69879c50d3', 'url' : createDownloadUrl('c0o6hcik3l', '1', name)}
    files.append(f0)
    name = 'bitcask-intro.pdf'
    f1 = {'name' : name, 'size' : '324579', 'md5' : '72fe4623357be8446ad673fb91077f00', 'url' : createDownloadUrl('c0kbn3obzv', '1', name)}
    files.append(f1)
    name = '2E0BDF62d01.pdf'
    f2 = {'name' : name, 'size' : '152336', 'md5' : '1231ca284634f7a225422d97afbacd8f', 'url' : createDownloadUrl('c0j743rkh8', '1', name)}
    files.append(f2)
    '''
    name = 'Getting Started.pdf'
    f3 = {'name' : name, 'size' : '127748', 'md5' : '2d75da7f0406283193cf04c3886c8574', 'url' : createDownloadUrl('c0n3la0jvh', '1', name)}
    files.append(f3)
    ret = svc.send(message_type, {'nsp.event.cid' : cid, 'action' : 'print', 'files' : files, 'source.uid' : uid, 'printer' : 'hp_p2015dn'})
    print ret

def createDownloadUrl(f, i, name):
    base_url = 'http://www.dbank.com/download'
    secret = 'Yd2I9xp0za1WfH6l'
    h = ('%s' % (time.time())).split('.')[0]
    v = md5('%s%s%s%s' % (f, i, h, secret)).hexdigest()[0:8]
    url = '%s/%s?f=%s&i=%s&h=%s&v=%s' % (base_url, quote_plus(name), f, i, h, v)
    return url

if __name__ == '__main__':
    sendMsg()
