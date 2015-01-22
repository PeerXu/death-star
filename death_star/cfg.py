import os
import ConfigParser

DEFAULT_CONFIG_LIST = ['./config.ini']

list_conv_func_maker = \
    lambda typ: lambda xs: [typ(x.strip()) for x in xs.split(',')]

CONV_FUNC = {
    'str': str,
    'int': int,
    'float': float,
    'bool': bool,
    'list(str)': list_conv_func_maker(str),
    'list(int)': list_conv_func_maker(int),
    'list(float)': list_conv_func_maker(float),
    'list(bool)': list_conv_func_maker(bool),
}

class Config(object):
    def __init__(self, conf_file):
        self._parser = ConfigParser.ConfigParser()
        self._parser.read(conf_file)

    def get(self, key):
        section, option = key.split('.')
        if section not in self._parser.sections():
            raise ConfigParser.NoSectionError(section)
        opts = self._parser.options(section)
        for _opt in opts:
            if '!' not in _opt:
                typ = 'str'
            else:
                opt, typ = _opt.split('!', 1)

            if opt == option:
                return self._parser._get(section, CONV_FUNC[typ], _opt)
        else:
            raise ConfigParser.NoOptionError(option)

for conf_file in DEFAULT_CONFIG_LIST:
    if os.path.exists(conf_file):
        CONF = Config(conf_file)
        break
