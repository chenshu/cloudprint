#!/usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import with_statement
import os
import sys
import os.path
import hashlib
from nsp import NSPClient
from time import sleep, time
import cookielib
from urllib import urlencode
from urllib2 import build_opener, HTTPCookieProcessor, HTTPError, URLError, Request
from urlparse import urlparse
import simplejson as sj
from subprocess import call
import random
import socket
import getpass
from hashlib import md5

appid = 50033
appsecret = 'Vulid3u3lVMBVRDbNJE0aI6QMKhjHiqK';
seed = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

class Client(object):
    '''cloud printer client'''

    def __init__(self, printer_name):
        # client id
        self.client = None
        # client secret
        self.secret = None
        # session for login
        self.session = None

        self.nsp = NSPClient(appid, appsecret)
        self.svc_auth = self.nsp.service('nsp.auth')

        # local directory
        self.dirname = os.path.dirname(os.path.realpath(__file__))

        # config info of client
        self.filename = '%s/client.conf' % (self.dirname)

        # check if client already init
        self.check()

        self.printer_name = printer_name

    def check(self):
        '''init client'''

        if not os.path.exists(self.filename):
            self.create()

        infos = dict()
        with open('%s' % (self.filename), 'r') as fp:
            for line in fp:
                k, v = line.strip().split('=')
                infos[k] = v
        self.__dict__.update(infos)

    def create(self):
        '''create client'''

        ret = self.svc_auth.createClient(1)
        if 'errCode' in ret or 'errMsg' in ret:
            raise RuntimeError, "create client failure: code=%s\tmsg=%s" % (ret['errCode'], ret['errMsg'])
        client = ret['client']
        secret = ret['secret']
        if client is None or client == '' \
                or secret is None or secret != '':
            raise RuntimeError, "create client failure: client=%s\tsecret=%s" % (client, secret)
        with open('%s' % (self.filename), 'w+') as fp:
            fp.write('client=%s\n' % (client))
            fp.write('secret=%s\n' % (secret))

    def login(self, username, password):
        '''sign in dbank account'''

        if username is None or username == '' \
                and password is None or password == '':
                    return False

        url = 'http://login.dbank.com/accounts/loginAuth'
        params = urlencode({'userDomain.user.email' : username, 'userDomain.user.password' : password, 'ru' : 'http://www.dbank.com/ServiceLogin.action'})
        self.cookie = cookielib.CookieJar()
        self.opener = build_opener(HTTPCookieProcessor(self.cookie))
        self.opener.addheaders = [
            ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
            ('Accept-Charset', 'GBK,utf-8;q=0.7,*;q=0.3'),
            ('Accept-Encoding', 'gzip,deflate,sdch'),
            ('Accept-Language', 'zh-CN,zh;q=0.8'),
            ('Connection', 'keep-alive'),
            ('Content-Type', 'application/x-www-form-urlencoded'),
            ('Host', 'http://login.dbank.com'),
            ('Origin', 'http://www.dbank.com'),
            ('Referer', 'http://www.dbank.com/'),
            ('User-Agent', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.63 Safari/535.7')
        ]
        request = Request(url, params)
        response = self.opener.open(request)
        info = response.info()
        cookies = self.cookie.make_cookies(response, request)
        for cookie in cookies:
            if cookie.name == 'client':
                self.client = cookie.value
            elif cookie.name == 'secret':
                self.secret = cookie.value
            elif cookie.name == 'session':
                self.session = cookie.value

        if self.client is None or self.client == '' \
                or self.secret is None or self.secret == '' \
                or self.session is None or self.session == '':
                    return False

        self.nsp = NSPClient(self.session, self.secret)
        self.svc_msg = self.nsp.service('nsp.user.push')
        return True

    def subscribe(self):
        '''subscribe message'''

        #self.message_type = 'nsp.cloudprint'
        self.message_type = 'nsp.push.resource'
        ret = self.svc_msg.subscribe(self.message_type)
        if ret is None or ret == '' \
                or 'nsp.http.query.status' not in ret or ret['nsp.http.query.status'] != '200':
                    return False

        interval = ret['nsp.http.query.interval']
        url = ret['nsp.http.query.url']
        return url

    def get(self, url, referer = ''):
        '''get method of http'''

        host = urlparse(url).hostname
        self.opener = build_opener()
        self.opener.addheaders = [
            ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
            ('Accept-Charset', 'GBK,utf-8;q=0.7,*;q=0.3'),
            ('Accept-Encoding', 'gzip,deflate,sdch'),
            ('Accept-Language', 'zh-CN,zh;q=0.8'),
            ('Connection', 'keep-alive'),
            ('Host', host),
            ('User-Agent', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.63 Safari/535.7')
        ]
        if referer is not None and referer != '':
            self.opener.addheaders.append(('Referer', referer))

        request = Request(url)
        response = self.opener.open(request)
        info = response.info()
        return response.read()

    def print_file(self, dirname, filename):
        '''print file by ext'''

        ext = os.path.splitext(filename)[1]
        if ext == '.pdf':
            pdf_file = '%s/%s' % (dirname, filename)
            ps_file = '%s/%s.ps' % (dirname, filename)
            #call(['/usr/bin/pdftops', pdf_file, ps_file])
            if not os.path.exists(ps_file):
                os.remove(pdf_file)
                return False
            #call(['/usr/bin/lpr', '-P', self.printer_name, ps_file])
            os.remove(ps_file)
        elif ext == '.txt':
            txt_file = '%s/%s' % (dirname, filename)
            #call(['/usr/bin/lpr', '-P', self.printer_name, txt_file])
        else:
            return False
        return True

    def createAuthUrl(self):
        machine = '%s@%s' % (getusername(), gethostname())
        h = ('%s' % (time())).split('.')[0]
        v = md5('%s%s%s%s' % (self.client, machine, self.printer_name, h)).hexdigest()[0:8]
        return 'http://apps.dbank.com/cloudprint/register.php?cid=%s&machine=%s&printer=%s&h=%s&v=%s' % (self.client, machine, self.printer_name, h, v)

def getusername():
    return getpass.getuser()

def gethostname():
    return socket.gethostname()

def generate(seed, n):
    if type(seed) is not list:
        seed = list(seed)
    return ''.join([random.choice(seed) for i in range(n) if random.shuffle(seed) is None])

def md5_for_data(data):
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()

def md5_for_file(fp, block_size=2**20):
    md5 = hashlib.md5()
    while True:
        data = fp.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.hexdigest()

def main(printer_name):
    print 'init client...'
    client = Client(printer_name)
    print 'login account...'
    auth_url = client.createAuthUrl()
    print 'url: %s' % (auth_url)
    ret = client.login('13810329910', 'xxxxxx')
    print 'client: ', client.client
    if ret is True:
        print 'connecting server...'
        url = client.subscribe()
        referer = ''
        if url is None or url is False:
            print 'could not connect server...'
            sys.exit(-1)
        while True:
            try:
                # 获取push消息
                ret = client.get(url, referer)
                print ret
                referer = url
                res = sj.loads(ret)
                header = res['header']
                if 'nsp.http.query.status' not in header or header['nsp.http.query.status'] != '200':
                    print 'error\t%s' % (ret)
                    sleep(10)
                    continue
                interval = header['nsp.http.query.interval']
                url = header['nsp.http.query.url']
                if interval != '0':
                    sleep(float(interval))
                continue
                if 'nsp.message.type' not in header or 'nsp.event.type' not in header:
                    continue
                if header['nsp.message.type'] != client.message_type or header['nsp.event.type'] != client.message_type:
                    print 'error\tmessage type error\t%s' % (header)
                    continue
                body = res['body']
                uid = body['nsp.event.uid'] if 'nsp.event.uid' in body else ''
                cid = body['nsp.event.cid'] if 'nsp.event.cid' in body else ''
                if (uid == '' and cid == '') or (cid != '' and cid != client.client):
                    print 'error\tmessage owner error\t%s\t%s\t%s' % (uid, cid, client.client)
                    continue
                print 'receiving message...'
                action = body['action']
                files = body['files']
                if action == 'print':
                    for f in files:
                        print 'downloading...', f['name'], f['size'], f['md5']
                        content = client.get(f['url'], 'http://www.dbank.com')
                        if len(content) != int(f['size']):
                            print 'error\tfile size error\t%s\t%s' % (len(content), int(f['size']))
                            continue
                        origin_file = '%s/%s' % (client.dirname, f['name'])
                        file_md5 = ''
                        with open(origin_file, 'w+') as fp:
                            file_md5 = md5_for_data(content)
                            if file_md5 != f['md5']:
                                print 'error\tfile md5 error\t%s\t%s' % (file_md5, f['md5'])
                                continue
                            fp.write(content)
                        print 'download success...'
                        print 'printing...'
                        ret = client.print_file(client.dirname, f['name'])
                        if ret is False:
                            print 'error\tprint error'
                            if not os.path.exists(origin_file):
                                os.remove(origin_file)
                            continue
                        if not os.path.exists(origin_file):
                            os.remove(origin_file)
                        print 'print success...'
                else:
                    pass
            except HTTPError, e:
                pass
            except URLError, e:
                pass
    else:
        print 'error\tlogin failure'

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'error\tneed printer name'
        sys.exit(-1)
    main(sys.argv[1])
