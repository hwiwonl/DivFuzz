import os

# Project settings
import platform

NAME = 'SHELLPHUZZ'
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BIN_DIR = os.path.join(PROJECT_ROOT, 'fuzzer/resources/bin')
AFL_DIR = os.path.join(BIN_DIR, 'afl-unix')
TRACER_DIR = os.path.join(BIN_DIR, 'tracers')

AFL_BIN = os.path.join(AFL_DIR, 'afl-fuzz')

BASE_WORK_DIR = '/tmp/' + NAME.lower()
if platform.system() == 'Linux':
    BASE_WORK_DIR = '/dev/shm/%s' % NAME.lower()
if not os.path.exists(BASE_WORK_DIR):
    os.makedirs(BASE_WORK_DIR)
