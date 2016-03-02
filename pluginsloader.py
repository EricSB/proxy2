#!/usr/bin/python
import os
import sys
import StringIO
import csv

#
# Plugin that attempts to load all of the supplied plugins from 
# program launch options.
class PluginsLoader:   
    def __init__(self, logger, options):
        self.options = options
        self.plugins = {}
        self.called = False
        self.logger = logger
        plugins_count = len(self.options['plugins'])

        if plugins_count > 0:
            self.logger.info('Loading %d plugin%s...' % (plugins_count, '' if plugins_count == 1 else 's'))
            
            for plugin in self.options['plugins']:
                self.load(plugin)

        self.called = True
        
    # Output format:
    #   plugins = {'plugin1': instance, 'plugin2': instance, ...}
    def get_plugins(self):
        return self.plugins

    #
    # Following function parses input plugin path with parameters and decomposes
    # them to extract plugin's arguments along with it's path.
    # For instance, having such string:
    #   -p "plugins/my_plugin.py",argument1="test",argument2,argument3=test2,argument3=test3
    #
    # It will return:
    #   {'path':'plugins/my_plugin.py', 'argument1':'test', 
    #       'argument2':'', 'argument3':['test2','test3']}
    #
    @staticmethod
    def decompose_path(p):
        decomposed = {}
        f = StringIO.StringIO(p)
        rows = list(csv.reader(f, quoting=csv.QUOTE_ALL, skipinitialspace=True))

        def append(d, k, v):
            if k in d:
                e = d[k]
                if type(e) == type([]):
                    d[k].append(v)
                elif type(e) == type(''):
                    d[k] = [e, v]
            else:
                d[k] = v

        for i in range(len(rows[0])):
            row = rows[0][i]
            if i == 0:
                decomposed['path'] = row
                continue

            if '=' in row:
                pos = row.find('=')
                append(decomposed, row[:pos], row[pos+1:])
            else:
                append(decomposed, row, '')

        return decomposed


    def load(self, path):
        instance = None

        self.logger.dbg('Plugin string: "%s"' % path)
        decomposed = PluginsLoader.decompose_path(path)
        self.logger.dbg('Decomposed as: %s' % str(decomposed))

        plugin = decomposed['path'].strip()
        name = os.path.basename(plugin).lower().replace('.py', '')

        if name in self.plugins:
            # Plugin already loaded.
            return

        self.logger.dbg('Attempting to load plugin: %s ("%s")...' % (name, plugin))
       
        try:
            sys.path.append(os.path.dirname(plugin))
            __import__(name)
            module = sys.modules[name]
            self.logger.dbg('Module imported.')

            try:
                handler = getattr(module, self.options['plugin_class_name'])
                
                # Call plugin's __init__ with the `logger' instance passed to it.
                instance = handler(self.logger, decomposed)
                
                self.logger.dbg('Found class "%s".' % self.options['plugin_class_name'])

            except AttributeError as e:
                self.logger.err('Plugin "%s" loading has failed: "%s".' % 
                    (name, self.options['plugin_class_name']))
                self.logger.err('\tError: %s' % e)
                return

            if not instance:
                self.logger.err('Didn\'t find supported class in module "%s"' % name)
            else:
                self.plugins[name] = instance
                self.logger.info('Plugin "%s" has been installed.' % name)

        except ImportError as e:
            self.logger.err('Couldn\' load specified plugin: "%s". Error: %s' % (plugin, e))