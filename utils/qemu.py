import contextlib
import glob
import os
import re
import resource
import shutil
import signal
import subprocess
import tempfile

import angr

from config import config
from fuzzer import get_or_create_angr_project
from tracer import TinyCore


class RunnerEnvironmentError(Exception):
    pass


class QEMURunner(object):
    """Trace an angr path with a concrete input using QEMU.
    """

    def __init__(self,
                 stdin: str,
                 argv: list = None,
                 binary_path: str = None,
                 bit_flip: bool = False,
                 exec_func: function = None,
                 ld_linux: str = None,
                 library_path: str = None,
                 memory_limit: str = '8G',
                 qemu_path: str = None,
                 record_core: bool = False,
                 record_stdout: bool = False,
                 record_trace: bool = True,
                 seed: int = None,
                 trace_log_limit: int = 1 << 30,
                 trace_timeout: int = 10,
                 use_tiny_core: bool = False):
        """
        :param stdin: Concrete input to feed to binary
        :param argv: binary parameters
        :param binary_path: tracer target binary path
        :param exec_func: Optional function to run instead of self._exec_func
        :param qemu_path: QEMU path
        :param record_core: Record the core file in case of crash
        :param record_stdout: Record the output of tracing process
        :param record_trace: Record the basic block trace
        :param seed: seed for QEMU pseudo-random number generator
        :param trace_log_limit: Dynamic trace log file size limit in bytes
        :param trace_timeout: Dynamic time limit in seconds
        :param use_tiny_core: Use minimal core loading
        """

        self.argv = argv
        self.binary_path = binary_path
        self.record_trace = record_trace
        self.record_core = record_core
        self.seed = seed
        self.stdin = stdin
        self.stdout = None
        self.qemu_path = qemu_path
        self.trace_log_limit = trace_log_limit
        self.trace_timeout = trace_timeout
        self.use_tiny_core = use_tiny_core
        self.exec_func = exec_func

        self.p = get_or_create_angr_project(binary_path)
        self.os = self.p.loader.main_object.os
        self.base_addr = self.p.loader.main_object.min_addr
        self.rebase = False

        self.trace = []
        self.registers = None
        self.state = None
        self.memory = None
        self.trace_source = None

        # Does the input cause a crash?
        self.crash_mode = False
        # If the input causes a crash, what address does it crash at?
        self.crash_addr = None

        self.tmout = False
        self.returncode = None

        if type(library_path) is str:
            library_path = [library_path]
        self.library_path = library_path
        self.ld_linux = ld_linux
        self._memory_limit = memory_limit
        self.bit_flip = bit_flip

        if self.seed is not None:
            if not isinstance(seed, int) or 0 < seed < 4294967295:
                raise ValueError('Invalid seed: %r' % seed)

        if record_stdout:
            fd, stdout_file_path = tempfile.mkstemp(
                prefix='stdout_' + os.path.basename(self.p.filename),
                dir=getattr(config, 'BASE_WORK_DIR'),
            )
            self._run(stdout_file=stdout_file_path)
            with open(stdout_file_path, 'rb') as f:
                self.stdout = f.read()
            os.close(fd)
            os.remove(stdout_file_path)
        else:
            self._run()

    def __get_rlimit_func(self):
        def set_rlimits():
            # limit the log size
            resource.setrlimit(
                resource.RLIMIT_CORE,
                (resource.RLIM_INFINITY, resource.RLIM_INFINITY),
            )
            resource.setrlimit(
                resource.RLIMIT_FSIZE,
                (self.trace_log_limit, self.trace_log_limit),
            )

        return set_rlimits

    @staticmethod
    @contextlib.contextmanager
    def _mk_tmpdir():
        tmpdir = tempfile.mkdtemp(prefix="/tmp/tracer_")
        try:
            yield tmpdir
        finally:
            with contextlib.suppress(FileNotFoundError):
                shutil.rmtree(tmpdir)

    @staticmethod
    @contextlib.contextmanager
    def _tmpfile(**kwargs):
        fd, tmpfile = tempfile.mkstemp(**kwargs)
        try:
            yield tmpfile
        finally:
            with contextlib.suppress(FileNotFoundError):
                os.close(fd)
                os.unlink(tmpfile)

    @contextlib.contextmanager
    def _exec_func(self,
                   qemu_variant,
                   qemu_args,
                   program_args,
                   ld_path=None,
                   stdin=None,
                   stdout=None,
                   stderr=None,
                   record_trace=True,
                   core_target=None):

        with self._mk_tmpdir() as tmpdir, contextlib.ExitStack() as exit_stack:
            cmd_args = [qemu_variant]
            cmd_args += qemu_args
            cmd_args += ["-C", tmpdir]

            # hardcode an argv[0]
            # cmd_args += [ "-0", program_args[0] ]

            # record the trace, if we want to
            if record_trace:
                fd, trace_filename = tempfile.mkstemp(dir="/dev/shm/",
                                                      prefix="tracer-log-")
                os.close(fd)
                cmd_args += ["-d", "exec", "-D", trace_filename]
            else:
                trace_filename = None
                cmd_args += ["-enable_double_empty_exiting"]

            if ld_path:
                cmd_args.append(ld_path)

            # and the program
            cmd_args += program_args

            # set up files
            stdin_file = subprocess.DEVNULL if stdin is None else exit_stack.enter_context(
                open(stdin, 'wb')) if type(stdin) is str else stdin
            stdout_file = subprocess.DEVNULL if stdout is None else exit_stack.enter_context(
                open(stdout, 'wb')) if type(stdout) is str else stdout
            stderr_file = subprocess.DEVNULL if stderr is None else exit_stack.enter_context(
                open(stderr, 'wb')) if type(stderr) is str else stderr

            r = {}
            r['process'] = subprocess.Popen(
                cmd_args,
                stdin=stdin_file, stdout=stdout_file, stderr=stderr_file,
                preexec_fn=self.__get_rlimit_func()
            )

            try:
                yield r
                r['returncode'] = r['process'].wait(timeout=self.trace_timeout)
                r['timeout'] = False

                # save the trace
                r['trace'] = ''
                if record_trace:
                    with open(trace_filename, 'rb') as tf:
                        r['trace'] = tf.read()

                # save the core and clean up the original core
                core_glob = glob.glob(os.path.join(tmpdir,
                                                   "qemu_" + os.path.basename(
                                                       program_args[
                                                           0]) + "_*.core"))

                if core_target and core_glob:
                    shutil.copy(core_glob[0], core_target)
                if core_glob:
                    os.unlink(core_glob[0])

            except subprocess.TimeoutExpired:
                r['process'].terminate()
                r['returncode'] = r['process'].wait()
                if record_trace and 'trace' not in r:
                    r['trace'] = b''
                r['timeout'] = True

        return r

    def _run(self, stdout_file=None):
        qemu_args = ['-E', 'LD_BIND_NOW=1']

        if self.bit_flip:
            qemu_args += ['-bitflip']

        if self.seed is not None:
            qemu_args += ['-seed', str(self.seed)]

        if self.library_path:
            qemu_args += [
                '-E', 'LD_LIBRARY_PATH=' + ':'.join(self.library_path),
            ]

        program_args = self.argv or [self.binary_path]

        in_s = subprocess.PIPE
        with self._tmpfile(prefix='tracer-core-') as core_target:
            with self.exec_func(
                self.qemu_path,
                qemu_args,
                program_args,
                ld_path=self.ld_linux,
                stdin=in_s,
                stdout=stdout_file,
                record_trace=self.record_trace,
                core_target=core_target if self.record_core else None
            ) as exec_details:
                exec_details['process'].communicate(self.stdin,
                                                    timeout=self.trace_timeout)

            self.returncode = exec_details['returncode']
            self.tmout = exec_details['timeout']

            # did a crash occur?
            if self.returncode < 0:
                if (abs(self.returncode) == signal.SIGSEGV
                    or abs(self.returncode) == signal.SIGILL):
                    self.crash_mode = True

                if self.record_core:
                    # find core file
                    a_mesg = "Empty core file generated"
                    assert os.path.getsize(core_target) > 0, a_mesg

                    if self.use_tiny_core:
                        self._load_tiny_core(core_target)
                    else:
                        self._load_core_values(core_target)

        if self.record_trace:
            try:
                trace = exec_details['trace']
                addrs = []

                # Find where qemu loaded the binary. Primarily for PIE
                qemu_base_addr = int(
                    trace.split(b"start_code")[1].split(b"\n")[0], 16)
                if (self.base_addr != qemu_base_addr
                    and self.p.loader.main_object.pic):
                    self.base_addr = qemu_base_addr
                    self.rebase = True

                prog = re.compile(br'Trace (.*) \[(?P<addr>.*)\].*')
                for t in trace.split(b'\n'):
                    m = prog.match(t)
                    if m is not None:
                        addr_str = m.group('addr')
                        addrs.append(int(addr_str, base=16))
                    else:
                        continue

                # grab the faulting address
                if self.crash_mode:
                    self.crash_addr = int(
                        trace.split(b'\n')[-2].split(b'[')[1].split(b']')[0],
                        16)

                self.trace = addrs
            except IndexError:
                pass

    def _load_core_values(self, core_file):
        p = angr.Project(core_file)
        self.registers = {
            reg: val
            for (reg, val) in p.loader.main_object.initial_register_values()
        }
        self.state = p.factory.entry_state()
        self.memory = self.state.memory

    def _load_tiny_core(self, core_file):
        tc = TinyCore(core_file)
        self.registers = tc.registers
        self.memory = None
