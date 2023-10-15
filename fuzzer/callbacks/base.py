from colorama import Fore

from fuzzer import Fuzzer
from utils import get_or_create_logger

__all__ = (
    'CallbackBase',
)


class CallbackBase(object):

    def __init__(self):
        self.logger = get_or_create_logger(
            self.__class__.__name__,
            stdout=True,
            color=Fore.YELLOW
        )

    def __call__(self, fuzzer: Fuzzer):
        return self.callback(fuzzer)

    def __str__(self):
        return '<%s>' % self.__class__.__name__

    def __repr__(self):
        return self.__str__()

    def callback(self, fuzzer: Fuzzer):
        raise NotImplementedError()

    def kill(self):
        raise NotImplementedError()
