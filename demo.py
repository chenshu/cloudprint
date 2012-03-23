#!/usr/bin/env python
# -*- coding:utf-8 -*-

from __future__ import with_statement
import os
import sys
import os.path
import hashlib
from nsp import NSPClient
from time import sleep
import cookielib
from urllib import urlencode
from urllib2 import build_opener, HTTPCookieProcessor, HTTPError, URLError, Request
from urlparse import urlparse
import simplejson as sj
from subprocess import call

appid = 50033
appsecret = 'Vulid3u3lVMBVRDbNJE0aI6QMKhjHiqK';

class Client(object):

    def __init__(self):
        self.client = None
        self.secret = None
        self.session = None
        self.nsp = NSPClient(appid, appsecret)
        self.svc_auth = self.nsp.service('nsp.auth')
        self.dirname = os.path.dirname(os.path.realpath(__file__))
        self.filename = '%s/client.conf' % (self.dirname)
        self.check()

    def check(self):
        if not os.path.exists(self.filename):
            self.create()
        infos = dict()
        with open('%s' % (self.filename), 'r') as fp:
            for line in fp:
                k, v = line.strip().split('=')
                infos[k] = v
        self.__dict__.update(infos)

    def create(self):
        ret = self.svc_auth.createClient(1)
        if 'errCode' in ret or 'errMsg' in ret:
            raise RuntimeError, "create client failure: code=%s\tmsg=%s" % (ret['errCode'], ret['errMsg'])
        client = ret['client']
        secret = ret['secret']
        if client is not None and client != '' \
                and secret is not None and secret != '':
                    with open('%s' % (self.filename), 'w+') as fp:
                        fp.write('client=%s\n' % (client))
                        fp.write('secret=%s\n' % (secret))

    def login(self, username, password):
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
        self.nsp = NSPClient(self.session, self.secret)
        self.svc_msg = self.nsp.service('nsp.user.push')
        return True

    def subscribe(self):
        self.message_type = 'nsp.app.cloudprint'
        ret = self.svc_msg.subscribe(self.message_type)
        if ret is None or ret == '' \
                or 'nsp.http.query.status' not in ret or ret['nsp.http.query.status'] != '200':
                    return False
        interval = ret['nsp.http.query.interval']
        url = ret['nsp.http.query.url']
        return url

    def get(self, url, referer = ''):
        host = urlparse(url).hostname
        self.opener = build_opener()
        self.opener.addheaders = [
            ('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
            ('Accept-Charset', 'GBK,utf-8;q=0.7,*;q=0.3'),
            ('Accept-Encoding', 'gzip,deflate,sdch'),
            ('Accept-Language', 'zh-CN,zh;q=0.8'),
            ('Connection', 'keep-alive'),
            ('Host', host),
            ('Referer', referer),
            ('User-Agent', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.63 Safari/535.7')
        ]

        request = Request(url)
        response = self.opener.open(request)
        info = response.info()
        return response.read()

def md5_for_file(fp, block_size=2**20):
    md5 = hashlib.md5()
    while True:
        data = fp.read(block_size)
        if not data:
            break
        md5.update(data)
    return md5.hexdigest()

def md5_for_data(data):
    md5 = hashlib.md5()
    md5.update(data)
    return md5.hexdigest()

def main():
    client = Client()
    print 'login...'
    ret = client.login('13810329910', 'xxxxxx')
    print 'client: ', client.client
    if ret is True:
        print 'connecting server...'
        url = client.subscribe()
        referer = ''
        while True:
            try:
                ret = client.get(url, referer)
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
                if 'nsp.message.type' not in header or header['nsp.message.type'] != client.message_type \
                        or 'nsp.event.type' not in header or header['nsp.event.type'] != client.message_type:
                            continue
                body = res['body']
                uid = body['nsp.event.uid'] if 'nsp.event.uid' in body else None
                cid = body['nsp.event.cid'] if 'nsp.event.cid' in body else None
                if uid is None and cid is None:
                    continue
                action = body['ac']
                data = body['data']
                if action == '1001':
                    files = data['files']
                    for f in files:
                        print 'downloading...', f['name'], f['size'], f['md5']
                        content = client.get(f['url'], 'http://www.dbank.com')
                        if len(content) != int(f['size']):
                            print 'error\tfile size error\t%s\t%s' % (len(content), int(f['size']))
                            continue
                        pdf_file = '%s/%s' % (client.dirname, f['name'])
                        file_md5 = ''
                        with open(pdf_file, 'w+') as fp:
                            file_md5 = md5_for_data(content)
                            if file_md5 != f['md5']:
                                print 'error\tfile md5 error\t%s\t%s' % (file_md5, f['md5'])
                                continue
                            fp.write(content)
                        print 'download success...'
                        print 'printing...'
                        ps_file = '%s/%s.ps' % (client.dirname, f['name'])
                        call(['/usr/bin/pdftops', pdf_file, ps_file])
                        if not os.path.exists(ps_file):
                            print 'error\tprint error'
                            os.remove(pdf_file)
                            continue
                        call(['/usr/bin/lpr', '-P', 'hp_p2015dn', ps_file])
                        os.remove(pdf_file)
                        os.remove(ps_file)
                        print 'print success'
                else:
                    pass
            except HTTPError, e:
                pass
            except URLError, e:
                pass
    else:
        print 'error\tlogin failure'

if __name__ == '__main__':
    main()
