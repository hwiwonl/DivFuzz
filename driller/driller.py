import binascii
import logging
import os
import pickle
import resource
import signal
import time

import angr

import tracer
from config import config
from fuzzer import get_or_create_angr_project

l = logging.getLogger("driller.driller")

__all__ = (
    'Driller',
)


class Driller(object):
    """Symbolically follows an input looking for new state transitions.
    """

    def __init__(self,
                 binary_path: str,
                 input_str: str,
                 fuzz_bitmap=None,
                 tag=None,
                 redis=None,
                 hooks=None,
                 argv=None):
        """
        :param binary_path: trace target binary path
        :param input_str: Input string to feed to the binary
        :param fuzz_bitmap: AFL bitmap of state transitions (default: empty)
        :param redis: redis instance for coordinating multiple Driller instances
        :param hooks: Dictionary of addresses to sim-procedures
        :param argv: Optionally specify argv params (i,e,: ['./calc', 'parm1']),
                     defaults to binary name with no params
        """

        self.binary_path = binary_path

        # Redis channel identifier.
        self.identifier = os.path.basename(binary_path)
        self.input_str = input_str
        self.fuzz_bitmap = fuzz_bitmap
        self.tag = tag
        self.redis = redis
        self.argv = argv or [binary_path]

        # The sim-procedures.
        self.hooks = {} if hooks is None else hooks

        # The driller core, which is now an exploration technique in angr.
        self.core = None

        # Start time, set by drill method.
        self.start_time = time.time()

        # Set of all the generated inputs.
        self._generated = set()

        # Set the memory limit specified in the config.
        if getattr(config, 'MEM_LIMIT') is not None:
            resource.setrlimit(
                resource.RLIMIT_AS,
                (config.MEM_LIMIT, config.MEM_LIMIT))

    def drill(self):
        """
        Perform the drilling, finding more code coverage based off existing
        input base.
        """

        # Don't re-trace the same input.
        if (self.redis
            and self.redis.sismember(
                self.identifier + '-traced', self.input_str)):
            return -1

        if self.redis:
            self.redis.sadd(self.identifier + '-traced', self.input_str)

        self.drill_input()

        return len(self._generated) if self.redis else self._generated

    def drill_generator(self, timeout=None):
        """A generator interface to the actual drilling.
        """
        timeout = timeout or getattr(config, 'DRILL_TIMEOUT')

        # Set up alarm for timeouts.
        if timeout is not None:
            signal.alarm(timeout)

        for i in self.drill_input():
            yield i

    def drill_input(self):
        """
        Symbolically step down a path with a tracer, trying to concretize
        inputs for un-encountered state transitions.
        """

        qemu_runner = tracer.qemu_runner.QEMURunner(
            self.binary_path, self.input_str, argv=self.argv)
        p = get_or_create_angr_project(self.binary_path)
        for addr, proc in self.hooks.items():
            p.hook(addr, proc)
            l.debug("Hooking %#x -> %s...", addr, proc.display_name)

        state = p.factory.full_init_state(stdin=angr.SimFileStream)
        state.preconstrainer.preconstrain_file(
            self.input_str, state.posix.stdin, set_length=True,
        )

        simgr = p.factory.simulation_manager(
            state,
            save_unsat=True,
            hierarchy=False,
            save_unconstrained=qemu_runner.crash_mode)

        exploration_tracer = angr.exploration_techniques.Tracer(
            trace=qemu_runner.trace,
            crash_addr=qemu_runner.crash_addr,
            copy_states=True)
        self.core = angr.exploration_techniques.DrillerCore(
            trace=qemu_runner.trace)

        simgr.use_technique(exploration_tracer)
        simgr.use_technique(angr.exploration_techniques.Oppologist())
        simgr.use_technique(self.core)

        self.set_concretizations(simgr.one_active)

        while (simgr.active
               and simgr.one_active.globals['trace_idx']
               < len(qemu_runner.trace) - 1):
            simgr.step()

            # Check here to see if a crash has been found.
            if (self.redis
                and self.redis.sismember(self.identifier + '-finished', True)):
                return

            if 'diverted' not in simgr.stashes:
                continue

            while simgr.diverted:
                state = simgr.diverted.pop(0)
                l.debug("Found a diverted state, exploring to some extent.")

                w = self.write_out(state.history.bbl_addrs[-1], state)
                if w is not None:
                    yield w
                for i in self.symbolic_explorer_stub(state):
                    yield i

    def symbolic_explorer_stub(self, state):
        """
        Create a new simulation manager and step it forward up to 1024
        accumulated active states or steps.
        """
        steps = 0
        accumulated = 1

        p = state.project
        state = state.copy()
        try:
            state.options.remove(angr.options.LAZY_SOLVES)
        except KeyError:
            pass
        simgr = p.factory.simulation_manager(state, hierarchy=False)

        l.debug(
            "[%s] started symbolic exploration at %s.",
            self.identifier, time.ctime(),
        )

        while len(simgr.active) and accumulated < 1024:
            simgr.step()
            steps += 1
            accumulated = steps * (len(simgr.active) + len(simgr.deadended))

        l.debug(
            "[%s] stopped symbolic exploration at %s.",
            self.identifier, time.ctime(),
        )

        for dumpable in simgr.deadended:
            try:
                if dumpable.satisfiable():
                    w = self.write_out(dumpable.history.bbl_addrs[-1], dumpable)
                    if w is not None:
                        yield w
            except IndexError:
                continue

    @staticmethod
    def set_concretizations(state):
        state.unicorn.concretization_threshold_memory = 50000
        state.unicorn.concretization_threshold_registers = 50000

    def in_catalogue(self, length, prev_addr, next_addr):
        """
        Check if a generated input has already been generated earlier during the
        run or by an another thread.

        :param length   : Length of the input.
        :param prev_addr: The source address in the state transition.
        :param next_addr: The destination address in the state transition.
        :return: boolean describing whether or not the input generated is
                 redundant.
        """

        key = '%x,%x,%x\n' % (length, prev_addr, next_addr)

        if self.redis:
            return self.redis.sismember(self.identifier + '-catalogue', key)
        else:
            # No redis means no coordination, so no catalogue.
            return False

    def add_to_catalogue(self, length, prev_addr, next_addr):
        if self.redis:
            key = '%x,%x,%x\n' % (length, prev_addr, next_addr)
            self.redis.sadd(self.identifier + '-catalogue', key)

    def write_out(self, prev_addr, state):
        generated = state.posix.stdin.load(0, state.posix.stdin.pos)
        generated = state.solver.eval(generated, cast_to=bytes)

        key = len(generated), prev_addr, state.addr

        # Checks here to see if the generation is worth writing to disk.
        # If we generate too many inputs which are not really different,
        # it will seriously slow down AFL.
        if self.in_catalogue(*key):
            self.core.encounters.remove((prev_addr, state.addr))
            return None
        else:
            self.add_to_catalogue(*key)
        self._generated.add((key, generated))

        l.debug(
            "[%s] dumping input for %#x -> %#x.",
            self.identifier, prev_addr, state.addr,
        )

        if self.redis:
            # Publish it out in real-time so that inputs get there immediately.
            channel = self.identifier + '-generated'

            self.redis.publish(
                channel,
                pickle.dumps({'meta': key, 'data': generated, 'tag': self.tag}),
            )
        else:
            l.debug("Generated: %s", binascii.hexlify(generated))

        return key, generated
