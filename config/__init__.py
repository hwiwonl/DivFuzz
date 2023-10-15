import os

__all__ = ('config',)

curr_dir = os.path.dirname(os.path.abspath(__file__))


def check_exists(name):
    config_path = os.path.join(curr_dir, '%s.py' % name)
    return os.path.exists(config_path)


def override_config(_config, name):
    if not check_exists(name):
        return _config

    obj = __import__(
        '%s.%s' % (__name__, name),
        globals(),
        locals(),
        ['object'],
        0,
    )
    for key in dir(obj):
        if key.isupper():
            setattr(_config, key, getattr(obj, key))
    return _config


def make_config_object():
    class Config(object):
        pass

    _config = Config()
    _config = override_config(_config, 'default')
    _config = override_config(_config, 'local')

    return _config


config = make_config_object()
