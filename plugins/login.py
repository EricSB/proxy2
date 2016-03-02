#!/usr/bin/python

#
# Plugin for auto-login functionality. When feeded with basic parameters like:
#     $ ./proxy2 -p plugins/login.py,url=http://example.com,params="login=test&pass=test"
#
# Will try to authenticate into specified form (parameter 'form') and based on that generate
# cookies to be injected in every handled request later on.
#

import re
import urlparse
import httplib
import cookielib
import urllib
import mechanize

VERSION = '0.1'
AUTHOR = 'mgeeky'
SCRIPT = 'Plugin[LOGIN]'
DEFAULT_VALID_PATTERN = 'hello|bonjour|welcome|wita|logout|logoff|signoff|signout|exit|quit|wylog|byebye'


class ProxyHandler:

    def __init__(self, logger, params):
        self.logger = logger
        self.params = params
        self.cookiejar = cookielib.CookieJar()
        self.cookie_header = ''

        if not self.validate_params(params):
            raise Exception(SCRIPT + ' improperly initialized.')

        logger.info(SCRIPT + " v%s by %s being initialized." % (VERSION, AUTHOR))
        logger.dbg("\tPerforming auto-login on: '%s'" % (params['url'] + params['form']))


    #
    # This plugin expects following parameters:
    #   - url       - web applications URL to be used during scoping
    #   - form      - web applications login form that will receive data.
    #   - params    - parameters to be sent in GET/POST request to the `form'.
    #   - valid     - regex pattern to validate whether login has succeeded or not.
    #   - verify    - verification URL that will be inspected for `valid' pattern.
    #   - header    - (optional) additional headers to be included in requests
    #   - cookie    - (optional) additional cookies to be included in requests
    #
    def validate_params(self, params):
        if 'url' not in params:
            self.logger.err(SCRIPT + ': Application URL not specified (parameter: "url").')
            return False
        if 'params' not in params:
            self.logger.err(SCRIPT + ': Authentication parameters not specified (parameter: "params").')
            return False

        if 'form' not in params:
            self.logger.err(SCRIPT + ': Authentication form URI not specified (parameter: "form"). Assuming default', noprefix=False)
            params['form'] = '/'
            self.logger.dbg(SCRIPT + ":\t'%s'" % params['form'])
        if 'valid' not in params:
            self.logger.dbg(SCRIPT + ': Valid session pattern not specified (parameter: "valid"). Assuming default' )
            params['valid'] = DEFAULT_VALID_PATTERN
            self.logger.dbg(SCRIPT + ":\t'%s'" % params['valid'])
        if 'verify' not in params:
            self.logger.trace(SCRIPT + ': Verification URI not specified (parameter: "verify"). Assuming default', noprefix=False)
            params['verify'] = '/'
            self.logger.dbg(SCRIPT + ":\t'%s'" % params['verify'])

        if type(params['url']) == type([]):
            self.logger.err(SCRIPT + ': Application URL has to be specified only once (parameter: "url").')
            return False
        if type(params['form']) == type([]):
            self.logger.err(SCRIPT + ': Authentication form URI has to be specified only once (parameter: "form").')
            return False
        if type(params['params']) == type([]):
            self.logger.err(SCRIPT + ': Authentication parameters have to be specified only once (parameter: "params").')
            return False
        if type(params['verify']) == type([]):
            self.logger.err(SCRIPT + ': Verification URI has to be specified only once (parameter: "verify").')
            return False

        for r in params['valid']:
            try:
                re.compile(r, re.I)
            except Exception as e:
                self.logger.err(SCRIPT + ": Specified validation pattern (%s) is not a valid Regexp!" % r)
                self.logger.err(SCRIPT + ":\t%s" % e)
                return False

        return True


    @staticmethod
    def get_origin(path):
        u = urlparse.urlsplit(path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        return (scheme, netloc)


    # Input: "X-My-Header: somevalue"
    # Output: {'X-My-Header': 'somevalue'}
    @staticmethod
    def string_to_dict(s):
        d = {}
        if ':' in s:
            pos = s.find(':')
            d[s[:pos].strip()] = s[pos+1:].strip()
        return d


    def check_is_valid(self, conn, req):

        hdrs = self.get_headers(req)
        verify = self.params['url'] + self.params['verify']
        self.logger.dbg(SCRIPT + ": Requesting for verify url: '%s'." % verify)

        # TODO: Add path, domain, httponly/secure, and more of such attributes.
        cook = ''
        for cookie in self.cookiejar:
            cook += '%s=%s; ' % (cookie.name, cookie.value)

        # Injecting session cookies
        hdrs.update({'Cookie':cook})

        conn[0].request('GET', verify, '', hdrs)
        res_body = conn[0].getresponse().read()

        def check(r):
            self.logger.dbg(SCRIPT + ": checking regex: '%s'" % r)
            m = re.search(r, res_body, re.I|re.M)
            if m is not None:
                return True
            return False

        if type(self.params['valid']) == type([]):
            for r in self.params['valid']:
                if check(r):
                    self.cookie_header = cook
                    return True

            return False
        else:
            b = check(self.params['valid'])
            if b:
                self.cookie_header = cook
            return b
            

    def get_headers(self, req):
        target_origin = ProxyHandler.get_origin(req.path)
        if target_origin[1]:
            req.headers['Host'] = target_origin[1]
        req_headers = self.proxy.filter_headers(req.headers)
        hdrs = {}
        
        if 'header' in self.params:
            for a in self.params['header']:
                hdrs.update(ProxyHandler.string_to_dict(a))
        hdrs.update(req_headers)
        
        return dict(hdrs)


    def get_connection(self, req):
        target_origin = ProxyHandler.get_origin(self.params['url'])
        self.logger.dbg(SCRIPT + ": request_handler(%s)" % str(ProxyHandler.get_origin(req.path)))
        
        if target_origin != ProxyHandler.get_origin(req.path):
            self.logger.dbg(SCRIPT + ":\tThis origin is not in scope.")
            return (False, False)

        conn = [None, False]
        if target_origin in self.proxy.tls.conns:
            self.logger.dbg(SCRIPT + ": Using already established connection.")
            conn[0] = self.proxy.tls.conns[target_origin]
        else:
            try:
                ctor = (httplib.HTTPSConnection if target_origin[0] == 'https' else httplib.HTTPConnection)
                self.proxy.tls.conns[target_origin] = ctor(target_origin[1], timeout=self.proxy.options['timeout'])
                self.logger.dbg(SCRIPT + ": Connection established.")
                conn[0] = self.proxy.tls.conns[target_origin]
                conn[1] = True
            except Exception as e:
                self.logger.dbg(SCRIPT + ": Couldn't initiate connection with origin %s:" % target_origin[1])
                self.logger.dbg(SCRIPT + ":\t%s" % e)
                return (False, False)

        return (True, conn)


    def request_handler(self, req, req_body):
        st, conn = self.get_connection(req)
        if not st:
            return req_body

        # Step 1: Sending request for verification url.
        if self.check_is_valid(conn, req):
            self.logger.trace(SCRIPT +  ": User is authenticated.", noprefix=False)
            req.headers['Cookie'] = self.cookie_header
            return req_body

        else:
            self.logger.trace(SCRIPT +  ": User is NOT authenticated.", noprefix=False)

            # Step 2: Perform user's authentication.
            if self.authenticate(conn, req):
                if self.check_is_valid(conn, req):
                    self.logger.info(SCRIPT + ": Autologin succeeded.", 
                        noprefix=False, color=self.logger.colors_map['green'])
                    req.headers['Cookie'] = self.cookie_header
                else:
                    self.logger.err(SCRIPT + ": Autologin failed.")

        return req_body

      
    def authenticate(self, conn, req):

        login = self.params['url'] + self.params['form']
        self.logger.dbg(SCRIPT + ": Requesting auth form: '%s'." % login)

        para = {}
        for p in self.params['params'].split('&'):
            k, v = p.split('=', 1)
            para[k] = v

        self.logger.dbg(SCRIPT + ': Params to issue: %s' % str(para))
        
        # Step 3: Issuing GET for authentication page containing desired form.
        opener = mechanize.build_opener(mechanize.HTTPCookieProcessor(self.cookiejar))
        opener.addheaders = self.get_headers(req).items()
        response = opener.open(login)
        hdrs2 = response.info().headers
        forms = mechanize.ParseResponse(response, backwards_compat=False)

        found = False
        form = None

        # Step 4: Finding and filling proper form with specified parameters.
        for f in forms:
            self.logger.dbg(SCRIPT + ": Parsing the form:\n%s" % f)
            try:
                for k, v in para.iteritems():
                    f.find_control(k)
                
                f.set_all_readonly(False)
                for k, v in para.iteritems():
                    c = f.find_control(k)
                    if c.type == 'select':
                        f[k] = [v,]
                    else:
                        f[k] = v

                found = True
                form = f
                self.logger.dbg(SCRIPT + ": form found.")
            except Exception as e:
                self.logger.dbg(SCRIPT + ": this is not the form we're looking for. Err: %s" % e)
                continue

        if found:
            request = form.click()

            # Step 5: Sending POST request with form being filled.
            self.logger.dbg(SCRIPT + ": Submitting the form:")
            self.logger.dbg("\t'%s'" % str(request.get_data()))

            resp = opener.open(request)

            return True

        else:
            return False


    def response_handler(self, req, req_body, res, res_body):
        return res_body

