from hashlib import md5
import time
import urllib
from php import dumps, loads

class NSPException(Exception):
    pass

class NSPClientCaller(object):
    def __init__(self, obj, svcname):
        self.obj = obj
        self.svcname = svcname

    def __getattr__(self, name):
        if self.svcname != None:
            name = "%s.%s" % (self.svcname, name)
        return NSPClientCaller(self.obj, name)

    def __call__(self, *args):
        return self.obj.callMethod(self.svcname, args)

class NSPURLopener(urllib.FancyURLopener):
    def http_error_default(self, url, fp, errcode, errmsg, headers):
        data = fp.read()
        fp.close()
        if errcode == 406:
            raise NSPException(loads(data))
        else:
            raise NSPException('HTTP Error: %s' % errmsg)

class NSPClient(object):
    def __init__(self, appid, secret, prefix='nsp'):
        self.nspUrl = 'http://api.dbank.com/rest.php'
        self.appid = appid
        self.secret = secret
        self.svc_prefix = prefix
        self._urlopener = NSPURLopener()

    def service(self, svcname):
        return NSPClientCaller(self, svcname)

    def signRequest(self, args):
        hasher = md5(self.secret)
        hasher.update(''.join(['%s%s' % (isinstance(x, unicode) and x.encode("utf-8") or x, isinstance(args[x], unicode) and args[x].encode("utf-8") or args[x]) for x in sorted(args.keys())]))
        return hasher.hexdigest().upper()

    def callMethod(self, svcname, param):
        postobj = {
                'nsp_fmt': 'php-rpc',
                'nsp_svc': svcname,
                'nsp_app': self.appid,
                'nsp_ts': int(time.time()),
                'nsp_params': dumps(param)
                }
        if len(str(self.appid))>32:
            postobj.pop('nsp_app')
            postobj['nsp_sid']  = self.appid

        postobj['nsp_key'] = self.signRequest(postobj)

        postdata = urllib.urlencode([(k, isinstance(postobj[k], unicode) and postobj[k].encode('utf-8') or postobj[k]) for k in postobj.keys()])
        o = self._urlopener.open(self.nspUrl, postdata)
        respdata = o.read()
        httpStatus = o.info().getheader('Status')
        nspStatus = o.info().getheader('NSP_STATUS')
        if httpStatus=='200' or httpStatus == None:
            if nspStatus == None:
                return loads(respdata)
            else:
                raise Exception(loads(respdata))
        else:
            raise NSPException(loads(respdata))
