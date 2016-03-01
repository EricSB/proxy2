#!/usr/bin/python

class ProxyHandler:

    def __init__(self, logger, params):
        self.logger = logger

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        pass