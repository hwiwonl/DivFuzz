import datetime
import logging
import os
import sys

from colorama import Style, Fore

__all__ = (
    'get_or_create_logger',
)


def get_or_create_logger(
    logger_name,
    log_dir=None,
    stdout=False,
    color=Fore.CYAN
):
    """
    A helper function to create function specific logger lazily.

    :param logger_name: logger name
    :param log_dir: save logger message into this directory if is not None
    :param stdout: write message to stdout if is True
    :param color: write message with `Fore` colors
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.INFO)
    if logger.handlers:
        return logger

    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    if log_dir is not None:
        if not os.path.exists(log_dir):
            os.makedirs(log_dir)
        now = datetime.datetime.utcnow().strftime('%Y-%m-%d')
        log_path = os.path.join(log_dir, '%s.%s.log' % (now, logger_name))
        handler = logging.FileHandler(log_path)
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    if stdout:
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_formatter = logging.Formatter(
            ''.join([
                Style.BRIGHT,
                Fore.MAGENTA, '%(asctime)s %(levelname)s: ',
                color, '%(message)s', Fore.RESET, Style.RESET_ALL,
            ])
        )
        stdout_handler.setFormatter(stdout_formatter)
        logger.addHandler(stdout_handler)

    return logger
