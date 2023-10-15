import os
import shutil
import subprocess
import tempfile

import angr

from config import config

__all__ = (
    'Showmap',
)


class Showmap(object):
    """Show map
    """

    def __init__(self, binary_path, testcase, timeout=None):
        """
        :param binary_path: path to the binary which the testcase applies to
        :param testcase: string representing the contents of the testcase
        :param timeout: millisecond timeout
        """
        self.binary_path = binary_path
        self.testcase = testcase
        self.timeout = str(timeout)

        self.causes_crash = False
        p = angr.Project(self.binary_path)
        self.showmap_path = os.path.join(
            getattr(config, 'AFL_DIR'),
            'afl-showmap',
        )
        self.afl_path_var = os.path.join(
            getattr(config, 'BIN_DIR'),
            'tracers',
            'qemu-' + p.arch.qemu_name,
        )
        os.environ['AFL_PATH'] = self.afl_path_var

        # create temp
        self.work_dir = tempfile.mkdtemp(prefix='showmap-', dir='/tmp/')

        # flag for work directory removal
        self._removed = False

        self.input_testcase = os.path.join(self.work_dir, 'testcase')
        self.output = os.path.join(self.work_dir, 'out')

        l.debug("input_testcase: %s", self.input_testcase)
        l.debug("output: %s", self.output)

        # populate contents of input testcase
        with open(self.input_testcase, 'wb') as f:
            f.write(testcase)

    def __del__(self):
        if not self._removed:
            shutil.rmtree(self.work_dir)

    def showmap(self):
        """Create the map
        """

        if self._start_showmap().wait() == 2:
            self.causes_crash = True

        with open(self.output) as f:
            result = f.read()

        shutil.rmtree(self.work_dir)
        self._removed = True

        shownmap = dict()
        for line in result.split("\n")[:-1]:
            key, h_count = map(int, line.split(":"))
            shownmap[key] = h_count

        return shownmap

    def _start_showmap(self, memory="8G"):

        args = [
            self.showmap_path,
            '-o', self.output,
            '-m', memory,
            '-Q',
        ]

        if self.timeout:
            args += ['-t', self.timeout]

        args += ['--', self.binary_path]
        args += self.binaries

        outfile = "minimizer.log"

        l.debug("execing: %s > %s", " ".join(args), outfile)

        outfile = os.path.join(self.work_dir, outfile)
        with open(outfile, "w") as fp, open(self.input_testcase,
                                            'rb') as it, open("/dev/null",
                                                              'wb') as devnull:
            return subprocess.Popen(args, stdin=it, stdout=devnull, stderr=fp,
                                    close_fds=True)
