from devlib.collector import (CollectorBase, CollectorOutput, CollectorOutputEntry)
import json
import tempfile

class BpfUtil:
    def __init__(self, target):
        self.target = target

    def has_probe(self, probe):
        res = self.target.execute('bpftrace -l {0}'.format(probe), as_root = True)
        return res.split('\n')[0] == probe

    def find_probe(self, probe):
        return self.target.execute('bpftrace -l {0}'.format(probe), as_root = True)

    def show_detail(self, probe):
        return self.target.execute('bpftrace -lv {0}'.format(probe), as_root = True)

class BpfMap:
    def __init__(self, mid, key):
        self.mid = mid
        self.key = key

    def __str__(self):
        return '@{0}[{1}]'.format(self.mid, self.key)

    def placeholder(self):
        return '{{' + self.mid + '}}'

class BpfHook:
    def __init__(self, target, cond, infos):
        self.target = target
        self.cond = ('/' +  cond + '/') or ''

        self.fmt_str = ', '.join([
            '\\"{0}\\": '.format(k) +
            ('\\"{0}\\"' if infos[k]['spec'] == '%s' else '{0}').format(infos[k]['spec'])
            for k in infos
        ])

        self.vals = ', '.join([
            infos[k]['val']
            for k in infos
        ])

        self.store_map_str = ''
        self.read_map_str = ''

    def __str__(self):
        trace_str = '\tprintf("{' + self.fmt_str + '}\\n", ' + self.vals + ');'
        if trace_str == '\tprintf("{}\\n", );':
            trace_str = ''

        return '\n'.join([
            self.target,
            self.cond,
            '{',
            self.store_map_str,
            trace_str,
            self.read_map_str,
            '}'
        ])

    def store_map(self, maps, stored):
        self.store_map_str = '\n'.join([
            '\t{0} = {1}'.format(str(maps[m]), stored[m])
            for m in stored
        ])

    def read_map(self, maps, read):
        self.read_map_str = '\n'.join([
            '\tdelete({0});'.format(maps[m])
            for m in read
        ])

        for m in read:
            self.vals = self.vals.replace(maps[m].placeholder(), str(maps[m]))

class BpfCodeGenerator:
    default_infos = {
            'timestamp': {'spec': '%lu', 'val': 'nsecs'},
            'probe': {'spec': '%s', 'val': 'probe'},
            'cpu': {'spec': '%d', 'val': 'cpu'},
            'pid': {'spec': '%lu', 'val': 'pid'},
            'tid': {'spec': '%lu', 'val': 'tid'},
            'comm': {'spec': '%s', 'val': 'comm'},
    }

    @staticmethod
    def build_maps(config):
        if 'maps' not in config:
            return {}

        maps = {}
        map_conf = config['maps']
        for m in map_conf:
            maps[m] = BpfMap(m, map_conf[m])

        return maps

    @staticmethod
    def build_hooks(config):
        maps = BpfCodeGenerator.build_maps(config)

        hooks = []
        hooks_conf = config['hooks']
        for target in hooks_conf:
            h_conf = hooks_conf[target]
            cond = h_conf['condition'] if 'condition' in h_conf else ''

            infos = {}
            if 'default_info' in h_conf and h_conf['default_info']:
                infos = dict(BpfCodeGenerator.default_infos)

            if 'custom_infos' in h_conf:
                infos.update(h_conf['custom_infos'])

            hook = BpfHook(target, cond, infos)
            if 'store_maps' in h_conf:
                hook.store_map(maps, h_conf['store_maps'])

            if 'read_maps' in h_conf:
                hook.read_map(maps, h_conf['read_maps'])

            hooks.append(hook)

        return hooks


    @staticmethod
    def gen_from_json(config):
        hooks = BpfCodeGenerator.build_hooks(config)
        return '\n\n'.join([str(hook) for hook in hooks])

    @staticmethod
    def gen_from_file(file_name):
        with open(file_name, 'r') as f:
            config = json.loads(f.read())
            return BpfCodeGenerator.gen_from_json(config)

class BpfCollector(CollectorBase):
    def __init__(self, target, config_file, output_path = ''):
        super(BpfCollector, self).__init__(target)
        self.output_path = output_path or '/tmp/bpf-result'

        self.logger.debug('Generating tracer from file {0}'.format(config_file))
        self.bt = BpfCodeGenerator.gen_from_file(config_file)

        self.trace_file = target.path.join(target.working_directory, 'trace.bt')
        self.out_file = target.path.join(target.working_directory, 'result')

        self.logger.debug('Deploying tracer to target: {0}'.format(target.hostname))
        with tempfile.NamedTemporaryFile(mode = 'w', encoding='utf8') as tf:
            tf.write(self.bt)
            tf.flush()

            self.target.push(tf.name, self.trace_file)

        self.running = False

    def reset(self):
        if self.running:
            self.stop()

        if self.target.file_exists(self.out_file):
            self.target.remove(self.out_file)

    def start(self):
        self.target.kick_off('bpftrace {0} -o {1}'.format(self.trace_file, self.out_file), as_root = True)
        self.running = True

    def stop(self):
        self.target.killall('bpftrace', as_root = True)
        self.__post_trace()
        self.running = False

    def get_data(self):
        self.logger.debug('Use {0} as output file'.format(self.output_path))

        self.target.pull('{0}.filt'.format(self.out_file), self.output_path)

        output = CollectorOutput()
        output.append(CollectorOutputEntry(self.output_path, 'file'))

        return output

    def __post_trace(self):
        self.target.execute('sync', as_root = True)
        self.target.execute('cat {0} | grep {1} > {0}.filt'.format(self.out_file, "'^\{.*\}$'"), as_root = True)
