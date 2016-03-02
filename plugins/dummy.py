#!/usr/bin/python

#
# Dummy plugin presenting necessary structure of a proxy2 plugin 
# to be loaded correctly. Every plugin will be set with a member
# called `proxy' referred to as self.proxy which will be holding
# instance of the caller's (ProxyRequestHandler from proxy2.py).
# Thanks to this object it will be feasible to leverage for instance
# self.proxy.tls list of HTTP/HTTPS connections.
#

class ProxyHandler:

    #
    # `logger' stands for logging object instance, `params' will be 
    # a dictonary of input paramerers for the script. Having passed to the
    # program a string like:
    #
    # $ ./proxy2 -p "plugins/my_plugin.py",argument1="test",argument2,argument3=test2
    #
    # This plugin shall receive:
    #
    # params =  {'path':'plugins/my_plugin.py', 
    #           'argument1':'test', 'argument2':'', 'argument3':'test2'}
    #
    def __init__(self, logger, params):
        self.logger = logger
        logger.info('hello world from __init__ in ProxyHandler.')
        if len(params) > 1:
            logger.info('\tI have received such params: %s' % str(params))

    def request_handler(self, req, req_body):
        self.logger.info('hello world from request_handler! Req: "%s"' % req.path)
        self.logger.info("My self.proxy is: %s" % str(self.proxy))

    def response_handler(self, req, req_body, res, res_body):
        self.logger.info('hello world from response_handler! Req: "%s"' % req.path)