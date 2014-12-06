#!/usr/bin/env python
# -*- coding:utf-8 -*-

import os
import sys
import time
import socket
import urllib
import os.path
import hashlib
import getpass
import logging
import urlparse
import threading
import tornado.web
import tornado.escape
import tornado.ioloop
import tornado.options
import tornado.httpclient
from tornado.options import define, options
from tornado.escape import json_encode, json_decode
from nsp import NSPClient
from subprocess import call
from datetime import datetime
from urllib import urlencode
from urllib2 import build_opener, HTTPCookieProcessor, HTTPError, URLError, Request

define("port", default=8888, help="run on the given port", type=int)
define("appid", default=50033, type=int)
define("appname", default=u'云打印', type=str)
define("appsecret", default=u'Vulid3u3lVMBVRDbNJE0aI6QMKhjHiqK', type=str)
#define("appsecret", default=u'test50033bba8df90acb8eb160a8087f', type=str)
define("printer", default=u'', type=str)
define("capability", default=u'nsp.cloudprint', type=str)

class Application(tornado.web.Application):
    def __init__(self, **kwargs):
        handlers = [
            (r"/cloudprint", MainHandler),
            (r"/cloudprint/auth/login", AuthLoginHandler),
            (r"/cloudprint/auth/logout", AuthLogoutHandler),
            (r"/cloudprint/register", RegisterHandler),
            (r"/cloudprint/manage", ManageHandler),
        ]
        settings = dict(
            cookie_secret="43oETzCXQAGaYdkL5gEiGeJJFuYX7EQnp2QdTP1o/Vo=",
            login_url="/cloudprint/auth/login",
            template_path=os.path.join("/etc/cloudprint", "templates"),
            static_path=os.path.join("/etc/cloudprint", "static"),
            xsrf_cookies=True,
            autoescape="xhtml_escape",
            debug=True,
            title="云打印",
        )
        if kwargs:
            settings.update(kwargs)
        tornado.web.Application.__init__(self, handlers, **settings)

class BaseHandler(tornado.web.RequestHandler):
    def get_current_user(self):
        sid = self.get_secure_cookie("sid")
        secret = self.get_secure_cookie("secret")
        if not sid or not secret:
            return None
        self.nsp_user = NSPClient(sid, secret)
        svc_user = self.nsp_user.service('nsp.user')
        ret = svc_user.getInfo(['user.uid', 'user.username'])
        if ret is None or 'user.uid' not in ret or ret['user.uid'] == '':
            return None
        self.uid = '%s' % (ret['user.uid'])
        self.username = '%s' % (ret['user.username'])
        user = {'uid' : self.uid, 'username' : self.username}
        self.nsp_app = NSPClient(options.appid, options.appsecret)
        return user

class NspMixin(object):

    _OPENID_ENDPOINT = "http://login.dbank.com/login.php"

    def _openid_args(self, callback_uri):
        url = urlparse.urljoin(self.request.full_url(), callback_uri)
        args = {"appid" : options.appid, "ru" : url}
        return args

    def authenticate_redirect(self, callback_uri=None):
        callback_uri = callback_uri or self.request.uri
        args = self._openid_args(callback_uri)
        self.redirect(self._OPENID_ENDPOINT + "?" + urllib.urlencode(args))

    def get_authenticated_user(self, callback):
        args = dict((k, v[-1]) for k, v in self.request.arguments.iteritems())
        sid = args['sid'] if 'sid' in args else None
        secret = args['secret'] if 'secret' in args else None
        callback(sid, secret)

class AuthLoginHandler(BaseHandler, NspMixin):
    @tornado.web.asynchronous
    def get(self):
        if self.get_argument("sid", None) and self.get_argument("secret", None):
            self.get_authenticated_user(self.async_callback(self._on_auth))
            return
        self.authenticate_redirect("/cloudprint?%s" % (self.request.query))

    def _on_auth(self, sid, secret):
        if not sid or not secret:
            raise tornado.web.HTTPError(500, "NSP auth failed")
        self.set_secure_cookie("sid", sid, None)
        self.set_secure_cookie("secret", secret, None)
        url = self.get_argument("next", '/cloudprint')
        self.redirect(url)

class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("sid")
        self.clear_cookie("secret")
        self.redirect('/cloudprint')

class MainHandler(BaseHandler):
    def get(self):
        if self.current_user is None:
            self.render("index.html")
            return
        self.render("home.html", message="login success")

class RegisterHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        client = self.settings['client']
        message = 'register success'
        channel = 'nsp'
        self.svc_push = self.nsp_app.service('nsp.push')
        token = getattr(client, 'token', None)
        if token is None:
            err = ''
            try:
                token = self.svc_push.register(client.client, channel, client.client);
                client.token = token
            except Exception, e:
                err = eval(str(e))['error']
            if token is False and err != 'client already binded by another push channel':
                message = 'register failure'
                self.render('home.html', message=message)
                return
            with open('%s' % (client.conf_file), 'a+') as fp:
                fp.write('token=%s\n' % (token))
            logging.info('push token:\t%s' % (token))

        machine = '%s@%s' % (getusername(), gethostname())
        attrs = {options.capability : {'client_id' : client.client, 'client_name' : machine, 'token' : token, 'channel' : channel, 'printer' : client.printer}}
        self.svc = self.nsp_user.service('nsp.app.capability')
        ret = self.svc.register(attrs)
        if ret is True:
            if getattr(client, 'admin', None) is None:
                client.admin = self.uid
                with open('%s' % (client.conf_file), 'a+') as fp:
                    fp.write('admin=%s\n' % (self.uid))
            if self.uid not in client.users:
                client.users[self.uid] = {'uid' : self.uid, 'username' : self.username, 'status' : '1', 'regdate' : datetime.now()}
                with open('%s' % (client.data_file), 'a+') as fp:
                    user = client.users[self.uid]
                    fp.write('%s\t%s\t%s\t%s%s' % (user['uid'], user['username'], user['status'], user['regdate'].strftime('%Y-%m-%d %H:%M:%S'), os.linesep))
        else:
            message = 'register failure'
        self.render('home.html', message=message)

class ManageHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        pass

class Client(object):
    '''cloud printer client'''

    def __init__(self, printers, http_client):
        # client id
        self.client = None
        # client secret
        self.secret = None

        self.nsp_app = NSPClient(options.appid, options.appsecret)

        # local directory
        #self.dirname = os.path.dirname(os.path.realpath(__file__))
        self.dirname = '/etc/cloudprint'

        self.conf_file = '%s/conf.ini' % (self.dirname)

        self.data_file = '%s/data.ini' % (self.dirname)

        # check if client already init
        self.check()

        self.nsp_push = NSPClient('%s@%s' % (self.client, options.appid), '%s@%s' % (self.secret, options.appsecret))

        self.printer = printers.split(',')

        self.http_client = http_client

    def check(self):
        '''init client'''

        infos = dict()
        if not os.path.exists(self.conf_file):
            self.create()
        with open('%s' % (self.conf_file), 'r') as fp:
            for line in fp:
                k, v = line.strip().split('=')
                infos[k] = v
        if 'client' not in infos or 'secret' not in infos:
            self.create()
        self.__dict__.update(infos)

        users = dict()
        if not os.path.exists(self.data_file):
            with open(self.data_file, 'w') as fp:
                pass
        else:
            with open(self.data_file, 'r') as fp:
                for line in fp:
                    uid, username, status, regdate = line.strip().split('\t')
                    users[uid] = {'uid' : uid, 'username' : username, 'status' : status, 'regdate' : datetime.strptime(regdate, '%Y-%m-%d %H:%M:%S')}
        self.__dict__['users'] = users

    def create(self):
        '''create client'''

        svc_auth = self.nsp_app.service('nsp.auth')
        ret = svc_auth.createClient(1)
        if 'errCode' in ret or 'errMsg' in ret:
            raise RuntimeError, "create client failure: %s" % (ret)
        self.client = ret['client']
        self.secret = ret['secret']
        if self.client is None or self.client == '' \
                or self.secret is None or self.secret == '':
            raise RuntimeError, "create client failure: %s" % (ret)
        with open('%s' % (self.conf_file), 'w+') as fp:
            fp.write('client=%s\n' % (self.client))
            fp.write('secret=%s\n' % (self.secret))

    def subscribe(self):
        '''subscribe message'''

        message_type = 'nsp.cloudprint'
        svc_push = self.nsp_push.service('nsp.user.push')
        ret = svc_push.subscribe(message_type)
        if ret is None or ret == '' \
                or 'nsp.http.query.status' not in ret or ret['nsp.http.query.status'] != '200':
                    raise RuntimeError, "subscribe message failure: %s" % (ret)
        interval = ret['nsp.http.query.interval']
        url = ret['nsp.http.query.url']
        return url

    def download(self, url, **headers):
        '''get method of http'''

        host = urlparse.urlparse(url).hostname
        opener = build_opener()
        opener.addheaders = [(k, headers[k]) for k in headers]
        opener.addheaders.append(('Host', host))
        request = Request(url)
        response = opener.open(request)
        info = response.info()
        return response.read()

    def print_file(self, dirname, filename, printer):
        '''print file by ext'''

        ext = os.path.splitext(filename)[1]
        if ext == '.pdf':
            pdf_file = '%s/%s' % (dirname, filename)
            ps_file = '%s/%s.ps' % (dirname, filename)
            call(['/usr/bin/pdftops', pdf_file, ps_file])
            if not os.path.exists(ps_file):
                return False
            call(['/usr/bin/lpr', '-P', printer, ps_file])
            os.remove(ps_file)
        elif ext == '.txt':
            txt_file = '%s/%s' % (dirname, filename)
            call(['/usr/bin/lpr', '-P', printer, txt_file])
        else:
            return False
        return True

    def handle_response(self, response):
        t = threading.Thread(target=self._handle, args=(response,))
        t.start()

    def _handle(self, response):
        waittime = time.time()
        if response.error:
            logging.error('response error:\t%s' % (response.error))
            url = self.subscribe()
            logging.info('push tunnel:\t%s' % (url))
            waittime = waittime + 10
        else:
            logging.info('response body:\t%s' % (response.body.decode('utf-8')))
            json = json_decode(response.body.decode('utf-8'))
            header = json['header']
            if 'nsp.http.query.status' not in header or header['nsp.http.query.status'] != '200':
                logging.error('response status error:\t%s' % (json))
                url = self.subscribe()
                logging.info('push tunnel:\t%s' % (url))
                waittime = waittime + 10
            else:
                interval = header['nsp.http.query.interval']
                url = header['nsp.http.query.url']
                if interval != '0':
                    waittime = waittime + float(interval)
                body = json['body']
                if 'nsp.message.type' in header and 'nsp.event.type' in header and body is not None:
                    source_uid = '%s' % (body['source.uid']) if 'source.uid' in body else ''
                    if source_uid in self.users and self.users[source_uid]['status'] == '1':
                        cid = body['nsp.event.cid']
                        action = body['action']
                        printer = body['printer']
                        files = body['files']
                        if action == 'print':
                            for f in files:
                                logging.info('downloading:\t%s\t%s\t%s' % (f['name'], f['size'], f['md5']))
                                headers = {
                                        'Accept' : 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                                        'Accept-Charset' : 'GBK,utf-8;q=0.7,*;q=0.3',
                                        'Accept-Encoding' : 'gzip,deflate,sdch',
                                        'Accept-Language' : 'zh-CN,zh;q=0.8',
                                        'Connection' : 'keep-alive',
                                        'User-Agent' : 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/535.7 (KHTML, like Gecko) Chrome/16.0.912.63 Safari/535.7',
                                        'Referer' : 'http://www.dbank.com'
                                }
                                content = self.download(f['url'], **headers)
                                if len(content) != int(f['size']):
                                    logging.error('file size error:\t%s\t%s\t%s' % (f['name'], len(content), int(f['size'])))
                                    continue
                                if not os.path.exists('%s/data/' % (self.dirname)):
                                    os.makedirs('%s/data/' % (self.dirname))
                                origin_file = '%s/data/%s' % (self.dirname, f['name'])
                                file_md5 = ''
                                with open(origin_file, 'w+') as fp:
                                    file_md5 = md5_for_data(content)
                                    if file_md5 != f['md5']:
                                        logging.error('file md5 error:\t%s\t%s\t%s' % (f['name'], file_md5, f['md5']))
                                        continue
                                    fp.write(content)
                                logging.info('download success:\t%s' % (f['name']))
                                logging.info('printing:\t%s' % (f['name']))
                                ret = self.print_file('%s/data/' % (self.dirname), f['name'], printer)
                                os.remove(origin_file)
                                if ret is False:
                                    logging.error('print error:\t%s' % (f['name']))
                                    continue
                                logging.info('print success:\t%s' % (f['name']))
                        elif action == 'config':
                            pass
        tornado.ioloop.IOLoop.instance().add_timeout(waittime, lambda: self.http_client.fetch(url, callback=self.handle_response, request_timeout=300))

def getusername():
    return getpass.getuser()

def gethostname():
    return socket.gethostname()

def createAuthUrl():
    return 'http://localhost:%s/cloudprint/register' % (options.port)

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

def main():
    # 解析命令行
    tornado.options.parse_command_line()
    # 必须指定一个printer
    if options.printer is None or options.printer == '':
        logging.error('printer necessary')
        sys.exit()
    # 使用curl实现的异步客户端
    tornado.httpclient.AsyncHTTPClient.configure('tornado.curl_httpclient.CurlAsyncHTTPClient')
    # 长链接客户端
    http_client = tornado.httpclient.AsyncHTTPClient()
    client = Client(options.printer, http_client)
    logging.info('init client:\t%s' % (client.client))
    url = client.subscribe()
    logging.info('push tunnel:\t%s' % (url))
    http_client.fetch(url, callback=client.handle_response, request_timeout=300)
    auth_url = createAuthUrl()
    logging.info('register url:\t%s' % (auth_url))
    app = Application(client = client)
    app.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()
