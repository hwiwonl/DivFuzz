import os
import signal
import subprocess
import threading
import time

from config import config
from fuzzer.common import create_angr_project
from utils import (
    core_pattern_check,
    child_scheduling_check,
    get_or_create_logger,
    extract_strings,
)

__all__ = (
    'Fuzzer',
)


class InstallError(Exception):
    pass


class Fuzzer(object):
    """
    Fuzzer object, spins up a fuzzing job on a binary

    Args:
        binary_path: Target binary path
        afl_count: The number of AFL instances
        afl_timeout: Each AFL instance timeout
        callback_interval: Time period for stuck callback
        crash_exploration_mode: AFL crash exploration mode activation
        create_dictionary: Extract string references from the binary
        extra_opts: Extra options to pass to AFL
        first_crash: Stop on the first crash
        memory: AFL child process memory limit
        qemu: QEMU utilization
        qemu_library_path: QEMU library path
        seeds: Initial seeds for fuzzer
        stuck_callback: Callback function when AFL has no pending fav's
        target_opts: Extra options to pass to the binary
        timeout: Fuzzer timeout
        work_dir: Fuzzer workspace
    """

    def __init__(self,
                 binary_path: str,
                 afl_count: int = 1,
                 afl_timeout: int = None,
                 callback_interval: int = None,
                 crash_exploration_mode: bool = False,
                 create_dictionary: bool = False,
                 extra_opts: list = None,
                 first_crash: bool = None,
                 memory: str = '8G',
                 qemu: bool = False,
                 qemu_library_path: str = None,
                 seeds: list = None,
                 stuck_callback: callable = None,
                 target_opts: [] = None,
                 timeout: int = None,
                 work_dir: str = None):
        self.binary_path = os.path.abspath(binary_path)
        self.afl_count = afl_count
        self.afl_timeout = afl_timeout
        self.crash_exploration_mode = crash_exploration_mode
        self.create_dictionary = create_dictionary
        self.extra_opts = [] if extra_opts is None else extra_opts
        self.first_crash = first_crash
        self.callback_interval = callback_interval
        self.library_path = qemu_library_path
        self.memory = memory
        self.qemu = qemu
        self.seeds = seeds
        self.stuck_callback = stuck_callback
        self.target_opts = [] if target_opts is None else target_opts
        self.time_limit = timeout
        self.work_dir = work_dir or getattr(config, 'BASE_WORK_DIR')

        self.afl_instances = []
        self.afl_path = os.path.join(getattr(config, 'AFL_DIR'), 'afl-fuzz')
        self.afl_path_var = None
        self.dictionary = None
        self.driller = None
        self.fn = os.path.basename(binary_path)
        self.fuzz_id = 0
        self.in_dir = None
        self.logger = get_or_create_logger(self.__class__.__name__, stdout=True)
        self.out_dir = None
        self.os = None
        self.resuming = False
        self.start_time = int(time.time())
        self.job_dir = os.path.join(self.work_dir, self.fn)

        if self.crash_exploration_mode:
            if seeds is None:
                raise ValueError("Crash mode requires seeds.")
            self.logger.info("AFL will be started in crash mode")

        self.validate_environment()

        self.setup()

    def __str__(self):
        return '<%s [%s]>' % (self.__class__.__name__, self.binary_path)

    def __repr__(self):
        return self.__str__()

    def __del__(self):
        self.kill()

    @property
    def stats(self):
        stats = {}
        if not os.path.isdir(self.out_dir):
            return stats

        for fuzzer_dir in os.listdir(self.out_dir):
            stat_path = os.path.join(self.out_dir, fuzzer_dir, 'fuzzer_stats')
            if not os.path.isfile(stat_path):
                continue

            stats[fuzzer_dir] = {}
            with open(stat_path, 'r') as f:
                stat = f.read()

            lines = stat.strip().split('\n')
            for line in lines:
                key, val = line.split(':')
                stats[fuzzer_dir][key.strip()] = val.strip()

        return stats

    @property
    def timed_out(self):
        if self.time_limit is None:
            return False
        return time.time() - self.start_time > self.time_limit

    def bitmap(self, fuzzer='fuzzer-master'):
        """
        Retrieve bitmap of a fuzzer named with `fuzzer`.
        Args:
            fuzzer: Fuzzer name

        Returns:
            str: Content of the bitmap.
        """
        if fuzzer not in os.listdir(self.out_dir):
            raise ValueError("Fuzzer '%s' does not exist" % fuzzer)

        bitmap_path = os.path.join(self.out_dir, fuzzer, 'fuzz_bitmap')
        if not os.path.exists(bitmap_path):
            return None

        with open(bitmap_path, 'rb') as f:
            return f.read()

    def create_dict(self, dict_file):
        """Create a dictionary of string references within binary
        """
        self.logger.info("Creating [%s] dictionary", self.fn)
        dfp = open(dict_file, 'w')
        for i, string in enumerate(extract_strings(self.binary_path)):
            dfp.write('string_%d="%s"\n' % (i, string))
        dfp.close()

    def timer_callback(self):
        if self.stuck_callback is None:
            return

        if ('fuzzer-master' in self.stats
            and 'pending_favs' in self.stats['fuzzer-master']
            and int(self.stats['fuzzer-master']['pending_favs']) == 0
            or self.callback_interval is not None):
            return self.stuck_callback(self)

    def export_qemu_library_path(self, qemu_name):
        """Export QEMU library path for a given architecture
        """
        path = None

        if self.library_path is None:
            directory = None
            if qemu_name == 'aarch64':
                directory = 'arm64'
            if qemu_name == 'i386':
                directory = 'i386'
            if qemu_name == 'x86_64':
                directory = 'x86_64'
            if qemu_name == 'mips':
                directory = 'mips'
            if qemu_name == 'mipsel':
                directory = 'mipsel'
            if qemu_name == 'ppc':
                directory = 'powerpc'
            if qemu_name == 'arm':
                with open(self.binary_path, 'rb') as f:
                    bin_data = f.read(0x800)
                if '/lib/ld-linux.so.3' in bin_data:
                    directory = 'armel'
                elif '/lib/ld-linux-armhf.so.3' in bin_data:
                    directory = 'armhf'

            if directory is None:
                self.logger.warning("Not supported architecture: " + qemu_name)
            else:
                path = os.path.join(
                    getattr(config, 'BIN_DIR'),
                    'fuzzer-libs',
                    directory,
                )
        else:
            path = self.library_path

        if path is not None:
            self.logger.info("Exporting QEMU_LD_PREFIX of '%s'", path)
            os.environ['QEMU_LD_PREFIX'] = path

    def found_crash(self):
        return len(self.get_crashes()) > 0

    def get_crashes(self,
                    signals=(signal.SIGSEGV, signal.SIGILL,),
                    excludes=('README.txt',)):
        """
        Retrieve discovered crashes.
        Args:
            signals (tuple): Valid kill signal numbers. Defaults to SIGSEGV and
                SIGILL.
            excludes (tuple): File names not to check. Defaults to README.txt

        Returns:
            list: Crashing inputs.
        """
        crashes = set()
        for fuzzer in os.listdir(self.out_dir):
            crashes_dir = os.path.join(self.out_dir, fuzzer, 'crashes')

            if not os.path.isdir(crashes_dir):
                continue

            for crash_fn in os.listdir(crashes_dir):
                if crash_fn in excludes:
                    continue

                attrs = {}
                for attr in crash_fn.split(','):
                    key, value = attr.split(':')
                    attrs[key] = value

                if int(attrs['sig']) not in signals:
                    continue

                crash_path = os.path.join(crashes_dir, crash_fn)
                with open(crash_path, 'rb') as f:
                    crashes.add(f.read())

        return crashes

    def initialize_seeds(self):
        """Populate input directory with seeds.
        """
        if not self.seeds:
            raise ValueError('You should provide at least one seed')

        self.logger.debug("Initializing seeds %r", self.seeds)

        template = os.path.join(self.in_dir, "seed-%d")
        for i, seed in enumerate(self.seeds):
            with open(template % i, 'wb') as f:
                f.write(seed)

    def kill(self):
        for p in self.afl_instances:
            p.terminate()
            p.wait()

        if self.driller is not None and not self.driller.finished.is_set():
            self.driller.cancel()

    def launch_afl_instances(self):
        """Start up AFL instances
        """
        master = self.start_afl_instance()
        self.afl_instances.append(master)

        if self.afl_count > 1:
            # TODO: fix variable name
            # Why did shellphish name afl process with 'driller'?
            driller = self.start_afl_instance()
            self.afl_instances.append(driller)

        for _ in range(2, self.afl_count):
            slave = self.start_afl_instance()
            self.afl_instances.append(slave)

    def pollenate(self, testcases):
        """
        Pollenate a fuzzing job with new test cases.
        Args:
            testcases (list): New inputs.
        """
        nectary_queue_directory = os.path.join(self.out_dir, 'pollen', 'queue')
        if 'pollen' not in os.listdir(self.out_dir):
            os.makedirs(nectary_queue_directory, exist_ok=True)

        pollen_cnt = len(os.listdir(nectary_queue_directory))
        for i, case in enumerate(testcases):
            pollen_path = os.path.join(
                nectary_queue_directory,
                'id:%06d,src:pollenation' % (pollen_cnt + i),
            )
            with open(pollen_path, 'w') as f:
                f.write(case)

    def queue(self, fuzzer='fuzzer-master'):
        """
        Retrieve current queue inputs for a fuzzer named with `fuzzer`.
        Args:
            fuzzer (str): Fuzzer name

        Returns:
            list: Queue inputs of fuzzer.
        """
        if fuzzer not in os.listdir(self.out_dir):
            raise ValueError("Fuzzer '%s' does not exist" % fuzzer)

        queue_dir = os.path.join(self.out_dir, fuzzer, 'queue')
        queue_files = filter(lambda x: x != ".state", os.listdir(queue_dir))

        queues = []
        for q in queue_files:
            queue_filepath = os.path.join(queue_dir, q)
            with open(queue_filepath, 'rb') as f:
                queues.append(f.read())

        return queues

    def setup(self):
        # Ready required directories
        self.in_dir = os.path.join(self.job_dir, 'input')
        self.out_dir = os.path.join(self.job_dir, 'sync')

        os.makedirs(self.job_dir, exist_ok=True)
        os.makedirs(self.in_dir, exist_ok=True)
        os.makedirs(self.out_dir, exist_ok=True)

        # Set afl and QEMU related variables
        p = create_angr_project(self.binary_path)
        self.afl_path_var = os.path.join(
            getattr(config, 'BIN_DIR'),
            'tracers',
            'qemu-' + p.arch.qemu_name,
        )
        self.os = p.loader.main_object.os

        # Set environment variables
        self.export_qemu_library_path(p.arch.qemu_name)
        os.environ['AFL_PATH'] = self.afl_path_var

        # Set fuzzer related variables
        dictionary = os.path.join(self.job_dir, '%s.dict' % self.fn)
        if os.path.exists(dictionary):
            self.dictionary = dictionary

        self.resuming = bool(os.listdir(self.out_dir))
        if not self.seeds:
            self.seeds = [b'fuzz']

        if not self.resuming:
            self.initialize_seeds()
            if self.create_dictionary:
                self.create_dict(dictionary)
                self.dictionary = dictionary
        else:
            self.in_dir = '-'

        # Create driller timer
        self.driller = threading.Timer(self.callback_interval,
                                       self.timer_callback)

    def start(self):
        self.launch_afl_instances()
        self.driller.start()

        self.logger.info(
            'Waiting for fuzzer completion (timeout: %s, first_crash: %s)',
            str(self.time_limit), str(self.first_crash),
        )

        while True:
            time.sleep(5)
            if self.found_crash():
                self.logger.info('Found a crash!')
                if self.first_crash:
                    break

            # Restart stuck callbacks (driller) if it has done
            if self.driller.finished.is_set():
                self.logger.info('Driller job has done. Prepare next driller.')
                self.driller = threading.Timer(self.callback_interval,
                                               self.timer_callback)
                self.driller.start()

            if self.timed_out:
                self.logger.info('Timeout reached.')
                break

    def start_afl_instance(self):
        """Spawn AFL instance process
        """

        args = [
            self.afl_path,
            '-i', self.in_dir,
            '-o', self.out_dir,
            '-m', self.memory,
        ]

        if self.qemu:
            args += ['-Q']

        if self.crash_exploration_mode:
            args += ['-C']

        if self.fuzz_id == 0:
            args += ['-M', 'fuzzer-master']
            outfile = 'fuzzer-master.log'
        else:
            args += ['-S', 'fuzzer-%d' % self.fuzz_id]
            outfile = 'fuzzer-slave-%d.log' % self.fuzz_id

        if self.dictionary is not None:
            args += ['-x', self.dictionary]

        if self.extra_opts is not None:
            args += self.extra_opts

        if self.afl_timeout:
            args += ['-t', '%d+' % self.afl_timeout]

        args += ['--', self.binary_path]
        args.extend(self.target_opts)

        # increment the fuzzer ID
        self.fuzz_id += 1

        out_path = os.path.join(self.job_dir, outfile)
        with open(out_path, 'w') as fp:
            return subprocess.Popen(args, stdout=fp, close_fds=True)

    @staticmethod
    def validate_environment():
        err = ""
        if not core_pattern_check():
            err += (
                "AFL Error: Pipe at the beginning of core_pattern\n"
                "Execute: "
                "echo core | sudo tee /proc/sys/kernel/core_pattern\n"
            )

        if not child_scheduling_check():
            err += (
                "AFL Warning: Need to make fork() children run first\n"
                "Execute: "
                "echo 1 | sudo tee /proc/sys/kernel/sched_child_runs_first\n"
            )

        if err:
            raise InstallError(err)
