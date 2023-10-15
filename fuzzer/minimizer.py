import os
import shutil
import subprocess
import tempfile

from colorama import Fore

from config import config
from fuzzer.common import get_or_create_angr_project
from utils import get_or_create_logger

__all__ = (
    'Minimizer',
)


class Minimizer(object):
    """Testcase minimizer"""

    def __init__(self, binary_path, testcase):
        """
        :param binary_path: path to the binary which the testcase applies to
        :param testcase: string representing the contents of the testcase
        """

        self.binary_path = binary_path
        self.testcase = testcase

        p = get_or_create_angr_project(binary_path)

        self.logger = get_or_create_logger(
            self.__class__.__name__,
            stdout=True,
            color=Fore.LIGHTRED_EX,
        )
        self.tmin_path = os.path.join(getattr(config, 'AFL_DIR'), 'afl-tmin')
        self.afl_path_var = os.path.join(
            getattr(config, 'BIN_DIR'),
            'tracers',
            'qemu-' + p.arch.qemu_name,
        )
        os.environ['AFL_PATH'] = self.afl_path_var

        self.work_dir = tempfile.mkdtemp(prefix='tmin-', dir='/tmp')
        self.input_testcase = os.path.join(self.work_dir, 'testcase')
        self.output_testcase = os.path.join(self.work_dir, 'minimized_result')

        with open(self.input_testcase, 'wb') as f:
            f.write(testcase)

    def __del__(self):
        if os.path.exists(self.work_dir):
            shutil.rmtree(self.work_dir)

    def minimize(self):
        """Start minimizing"""

        self._start_minimizer().wait()

        with open(self.output_testcase, 'rb') as f: result = f.read()

        shutil.rmtree(self.work_dir)

        return result

    def _start_minimizer(self, memory="8G"):
        args = [
            self.tmin_path,
            '-i', self.input_testcase,
            '-o', self.output_testcase,
            '-m', memory,
            '-Q',
            '--', self.binary_path,
        ]
        outfile = 'minimizer.log'
        self.logger.debug("Run command: %s > %s", " ".join(args), outfile)

        outfile = os.path.join(self.work_dir, outfile)
        with open(outfile, 'wb') as fp:
            return subprocess.Popen(args, stderr=fp)
