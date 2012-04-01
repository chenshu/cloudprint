#!/usr/bin/env python
# -*- coding:utf-8 -*-

import os
import time
import socket
import urllib
import os.path
import getpass
import logging
import urlparse
import tornado.web
import tornado.escape
import tornado.ioloop
import tornado.options
import tornado.httpclient
from tornado.options import define, options
from tornado.escape import json_encode, json_decode
from hashlib import md5
from nsp import NSPClient

define("port", default=8888, help="run on the given port", type=int)
define("appid", default=50033, type=int)
define("appname", default='云打印', type=str)
define("appsecret", default='Vulid3u3lVMBVRDbNJE0aI6QMKhjHiqK', type=str)
define("printer", default='hp_p2015dn,P2015dn', type=str)
define("capability", default='nsp.cloudprint', type=str)

class Application(tornado.web.Application):
    def __init__(self, **kwargs):
        handlers = [
            (r"/cloudprint/", MainHandler),
            (r"/cloudprint/auth/login", AuthLoginHandler),
            (r"/cloudprint/auth/logout", AuthLogoutHandler),
            (r"/cloudprint/register", RegisterHandler),
        ]
        settings = dict(
            cookie_secret="43oETzKXQAGaYdkL5gEmGeJJFuYh7EQnp2XdTP1o/Vo=",
            login_url="/cloudprint/auth/login",
            template_path=os.path.join(os.path.dirname(__file__), "templates"),
            static_path=os.path.join(os.path.dirname(__file__), "static"),
            xsrf_cookies=True,
            autoescape="xhtml_escape",
            debug=True,
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
        return True

class MainHandler(BaseHandler):
    def get(self):
        self.render("index.html")

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
        self.authenticate_redirect("/cloudprint/?%s" % (self.request.query))

    def _on_auth(self, sid, secret):
        if not sid or not secret:
            raise tornado.web.HTTPError(500, "NSP auth failed")
        self.set_secure_cookie("sid", sid, None)
        self.set_secure_cookie("secret", secret, None)
        url = self.get_argument("next")
        self.redirect(url)

class AuthLogoutHandler(BaseHandler):
    def get(self):
        self.clear_cookie("sid")
        self.clear_cookie("secret")
        self.write("You are now logged out")

class RegisterHandler(BaseHandler):
    @tornado.web.authenticated
    def get(self):
        sid = self.get_secure_cookie("sid")
        secret = self.get_secure_cookie("secret")
        machine = '%s@%s' % (getusername(), gethostname())
        self.nsp = NSPClient(sid, secret)
        attrs = {options.capability : {'app_name' : options.appname, 'client_id' : self.application.settings['client'].client, 'client_name' : machine, 'printer' : self.application.settings['client'].printer}}
        self.svc = self.nsp.service('nsp.app.capability')
        ret = self.svc.register(attrs)
        if ret is True:
            # TODO update config
            self.write('register success<br/>')
        else:
            self.write('register failure<br/>')
        self.write('<a href="/cloudprint/auth/logout">Logout</a>')

class Client(object):
    '''cloud printer client'''

    def __init__(self, printers, http_client):
        # client id
        self.client = None
        # client secret
        self.secret = None
        # session for login
        self.session = None

        self.nsp = NSPClient(options.appid, options.appsecret)
        self.svc_auth = self.nsp.service('nsp.auth')

        # local directory
        self.dirname = os.path.dirname(os.path.realpath(__file__))

        # config info of client
        self.filename = '%s/client.conf' % (self.dirname)

        # check if client already init
        self.check()

        self.printer = printers.split(',')

        self.http_client = http_client

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
                or secret is None or secret == '':
            raise RuntimeError, "create client failure: client=%s\tsecret=%s" % (client, secret)
        with open('%s' % (self.filename), 'w+') as fp:
            fp.write('client=%s\n' % (client))
            fp.write('secret=%s\n' % (secret))

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

    def handle_request(self, response):
        if response.error:
            print "Error:", response.error
        else:
            json = json_decode(response.body)
            print "Fetched " + str(len(json["entries"])) + " entries " + "from the FriendFeed API"
        tornado.ioloop.IOLoop.instance().add_timeout(time.time() + 10, lambda: self.http_client.fetch("http://friendfeed-api.com/v2/feed/bret", callback=self.handle_request))

def getusername():
    return getpass.getuser()

def gethostname():
    return socket.gethostname()

def createAuthUrl():
    return 'http://localhost:%s/cloudprint/register' % (options.port)

def main():
    tornado.httpclient.AsyncHTTPClient.configure('tornado.curl_httpclient.CurlAsyncHTTPClient')
    http_client = tornado.httpclient.AsyncHTTPClient()
    print 'init client...'
    client = Client(options.printer, http_client)
    print 'client: ', client.client
    url = createAuthUrl()
    print url
    # TODO subscribe
    tornado.options.parse_command_line()
    app = Application(client = client)
    app.listen(options.port)
    http_client.fetch("http://friendfeed-api.com/v2/feed/bret", callback=client.handle_request)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == "__main__":
    main()
