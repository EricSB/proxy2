#!/usr/bin/python

# To be used as a default proxy logging facility.

import time
import sys
import traceback


class ProxyLogger:
    options = {}

    colors_map = {
        'red':      31, 
        'green':    32, 
        'yellow':   33,
        'blue':     34, 
        'magenta':  35, 
        'cyan':     36,
        'white':    37, 
        'grey':     38,
    }

    colors_dict = {
        'error': colors_map['red'],
        'trace': colors_map['magenta'],
        'info ': colors_map['white'],
        'debug': colors_map['yellow'],
        'other': colors_map['grey'],
    }

    def __init__(self, options):
        self.options = options

    @staticmethod
    def with_color(c, s):
        return "\x1b[%dm%s\x1b[0m" % (c, s)
        

    # Invocation:
    #   def out(txt, mode='info ', fd=None, color=None, noprefix=False, newline=True):
    @staticmethod
    def out(txt, fd, mode='info ', **kwargs):
        if txt == None or fd == 'none':
            return 
        elif fd == None:
            raise Exception('[ERROR] Logging descriptor has not been specified!')

        args = {
            'color': None, 
            'noprefix': False, 
            'newline': True,
        }
        args.update(kwargs)

        if args['color']:
            col = args['color']
        else:
            col = ProxyLogger.colors_dict.setdefault(mode, ProxyLogger.colors_map['grey'])

        tm = str(time.strftime("%H:%M:%S", time.gmtime()))

        prefix = ''
        if not args['noprefix']:
            prefix = ProxyLogger.with_color(ProxyLogger.colors_dict['other'], '[%s] %s: ' 
                % (mode.upper(), tm))
        
        nl = ''
        if 'newline' in args:
            if args['newline']:
                nl = '\n'

        fd.write(prefix + ProxyLogger.with_color(col, txt) + nl)

    # Info shall be used as an ordinary logging facility, for every desired output.
    def info(self, txt, **kwargs):
        ProxyLogger.out(txt, self.options['log'], 'info', **kwargs)

    # Trace by default does not uses [TRACE] prefix. Shall be used
    # for dumping packets, headers, metadata and longer technical output.
    def trace(self, txt, **kwargs):
        if self.options['trace']:   
            if 'noprefix' not in kwargs:
                kwargs['noprefix'] = True
            ProxyLogger.out(txt, self.options['log'], 'trace', **kwargs)


    def dbg(self, txt, **kwargs):
        if self.options['debug']:
            ProxyLogger.out(txt, self.options['log'], 'debug', **kwargs)

    def err(self, txt, **kwargs):
        ProxyLogger.out(txt, self.options['log'], 'error', **kwargs)

    @staticmethod
    def fatal_error(txt, e):
        print ProxyLogger.with_color(ProxyLogger.colors_map['red'], 'Fatal error has occured:\n\t%s' % txt)
        print ProxyLogger.with_color(ProxyLogger.colors_map['red'], '\t%s\nTraceback:' % e)
        print ProxyLogger.with_color(ProxyLogger.colors_map['red'], '-'*30)
        traceback.print_exc()
        print ProxyLogger.with_color(ProxyLogger.colors_map['red'], '-'*30)