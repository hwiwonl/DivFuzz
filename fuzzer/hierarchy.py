import glob
import os
import re
import subprocess
from collections import defaultdict

import networkx
import tqdm
from colorama import Fore

from utils import get_or_create_logger

__all__ = (
    'Input',
    'InputHierarchy',
)


class Input(object):
    def __init__(self, filename, instance, hierarchy):
        self.hierarchy = hierarchy
        self.instance = instance
        self.filename = filename

        self.id = None
        self.source_ids = []
        self.sources = []
        self.cov = False
        self.op = None
        self.synced_from = None
        self.other_fields = {}
        self.val = None
        self.rep = None
        self.pos = None
        self.orig = None
        self.crash = False
        self.sig = None
        self.process_filename(filename)

        self.looped = False
        self.timestamp = os.stat(self.filepath).st_mtime
        self.logger = get_or_create_logger(
            self.__class__.__name__,
            stdout=True,
            color=Fore.MAGENTA,
        )

        # cached stuff
        self._trace = None
        self._origins = None
        self._contributing_techniques = None
        self._technique_contributions = None

    def process_filename(self, filename):
        # process the fields
        fields = filename.split(',')
        for f in fields:
            if f == "+cov":
                self.cov = True
            elif f == "grease":
                self.orig = "greased_%s" % self.id
            else:
                n, v = f.split(':', 1)
                if n == 'id':
                    self.id = v
                elif n == 'src':
                    self.source_ids = v.split('+')
                elif n == 'sync':
                    self.synced_from = v
                elif n == 'op':
                    self.op = v
                elif n == 'rep':
                    self.rep = v
                elif n == 'orig':
                    self.orig = v
                elif n == 'pos':
                    self.pos = v
                elif n == 'val':
                    self.val = v
                elif n == 'from':  # driller uses this instead of synced/src
                    instance, from_id = v[:-6], v[-6:]
                    self.synced_from = instance
                    self.source_ids.append(from_id)
                elif n == 'sig':
                    self.crash = True
                    self.sig = v
                    self.id = 'c' + self.id
                else:
                    self.logger.warning(
                        "Got unexpected field %s with value %s for file %s.",
                        n, v, filename,
                    )
                    self.other_fields[n] = v

    def resolve_sources(self):
        try:
            if self.synced_from:
                self.sources = [
                    self.hierarchy.instance_input(
                        self.synced_from,
                        self.source_ids[0],
                    ),
                ]
            else:
                self.sources = [
                    self.hierarchy.instance_input(self.instance, i)
                    for i in self.source_ids
                ]
        except KeyError as e:
            l.warning("Unable to resolve source ID %s for %s", e, self)
            self.sources = []

    @property
    def filepath(self):
        return os.path.join(
            self.hierarchy._dir, self.instance,
            'crashes' if self.crash else 'queue', self.filename
        )

    def read(self):
        with open(self.filepath) as f:
            return f.read()

    def __repr__(self):
        s = "<Input inst:%s,%s>" % (self.instance, self.filename)
        # if self.synced_from:
        #   s += " sync:%s" % self.synced_from
        # s += "src:%s" % self.source_ids
        return s

    #
    # Lineage analysis.
    #

    @property
    def lineage(self):
        for p in self.sources:
            for pl in p.lineage:
                yield pl
        yield self

    def print_lineage(self, depth=0):
        if depth:
            print(' ' * depth + str(self))
        else:
            print(self)
        for parent in self.sources:
            parent.print_lineage(depth=depth + 1)

    @property
    def origins(self, follow_extensions=False):
        """
        Return the origins of this seed.
        """
        if self._origins is not None:
            return self._origins

        if not follow_extensions and not self.instance.startswith('fuzzer-'):
            o = {self}
        elif not self.sources:
            o = {self}
        else:
            o = set.union(*(s.origins for s in self.sources))
        self._origins = o
        return self._origins

    @property
    def technique(self):
        return 'fuzzer' if self.instance.startswith(
            'fuzzer-') else self.instance

    @property
    def contributing_techniques(self):
        if self._contributing_techniques is None:
            # don't count this current technique if we synced it
            if self.synced_from:
                new_technique = frozenset()
            else:
                new_technique = frozenset([self.technique])
            self._contributing_techniques = frozenset.union(
                new_technique,
                *(i.contributing_techniques for i in self.sources)
            )
        return self._contributing_techniques

    @property
    def contributing_instances(self):
        return set(i.instance for i in self.lineage)

    @property
    def output(self):
        with open('/dev/null', 'w') as tf, open(self.filepath) as sf:
            cmd_args = [
                'timeout', '60', shellphish_qemu.qemu_path('cgc-tracer'),
                self.hierarchy._fuzzer.binary_path
            ]
            process = subprocess.Popen(cmd_args, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=tf)
            fuck, _ = process.communicate(sf.read())

        return fuck

    @property
    def trace(self):
        if self._trace is not None:
            return self._trace

        with open(self.filepath) as sf:
            cmd_args = [
                'timeout', '2',
                shellphish_qemu.qemu_path('cgc-tracer'),
                '-d', 'exec',
                self.hierarchy._fuzzer.binary_path
            ]
            # print("cat %s | %s" % (self.filepath, ' '.join(cmd_args)))
            process = subprocess.Popen(cmd_args, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            _, you = process.communicate(sf.read())

        trace = []
        for tline in you.split('\n'):
            result = re.match(r'Trace 0x[0-9a-fA-F]* \[([0-9a-fA-F]*)\]',
                              tline.strip())
            if not result:
                continue
            trace.append(int(result.group(1), base=16))

        self._trace = trace
        return trace

    @property
    def transitions(self):
        return [(self.trace[i], self.trace[i + 1]) for i in
                range(len(self.trace) - 1)]

    @property
    def transition_set(self):
        return set(self.transitions)

    @property
    def new_transitions(self):
        if self.sources:
            return self.transition_set - set.union(
                *(s.transition_set for s in self.sources))
        else:
            return self.transition_set

    @property
    def block_set(self):
        return set(self.trace)

    @property
    def new_blocks(self):
        if self.sources:
            return self.block_set - set.union(
                *(s.block_set for s in self.sources))
        else:
            return self.block_set

    @property
    def technique_contributions(self):
        if self._technique_contributions is not None:
            return self._technique_contributions

        results = {
            self.contributing_techniques: self.new_transitions
        }
        if self.sources:
            for s in self.sources:
                for k, v in s.technique_contributions.items():
                    results.setdefault(k, set()).update(v)
        self._technique_contributions = results
        return results

    @property
    def contribution_counts(self):
        return {
            k: len(v) for k, v in self.technique_contributions.iteritems()
        }


class InputHierarchy(object):
    """
    This class deals with the AFL input hierarchy and analyses done on it.
    """

    def __init__(self, fuzzer=None, fuzzer_dir=None, load_crashes=False):
        self._fuzzer = fuzzer
        self._dir = fuzzer_dir if fuzzer_dir is not None else fuzzer.job_dir
        self.inputs = {}
        self.instance_inputs = {}
        self.instances = []
        self.reload(load_crashes)
        self.logger = get_or_create_logger(
            self.__class__.__name__,
            stdout=True,
            color=Fore.LIGHTMAGENTA_EX,
        )

        while self._remove_cycles():
            pass

    def _remove_cycles(self):
        """Remove cycles in hierarchies.
        """

        graph = self.make_graph()
        cycles = networkx.simple_cycles(graph)
        if not cycles:
            return False
        else:
            cycles[0][0].looped = True
            cycles[0][0].sources[:] = []
            return True

    def triggered_blocks(self):
        """
        Gets the triggered blocks by all the testcases.
        """
        return set.union(
            *(i.block_set for i in tqdm.tqdm(self.inputs.values())))

    def crashes(self):
        """
        Returns the crashes, if they are loaded.
        """
        return [i for i in self.inputs.values() if i.crash]

    def technique_contributions(self):
        """
        Get coverage and crashes by technique.
        """
        results = {}
        for s, (b, c) in self.seed_contributions():
            results.setdefault(s.instance.split('-')[0], [0, 0])[0] += b
            results.setdefault(s.instance.split('-')[0], [0, 0])[1] += c
        return results

    def seed_contributions(self):
        """
        Get the seeds (including inputs introduced by extensions) that
        resulted in coverage and crashes.
        """
        sorted_inputs = sorted((
            i for i in self.inputs.values() if i.instance.startswith('fuzzer-')
        ), key=lambda j: j.timestamp)

        found = set()
        contributions = defaultdict(
            lambda: {'coverages': set(), 'crashes': set()}
        )
        for seed in tqdm.tqdm(sorted_inputs):
            origins = max(seed.origins, key=lambda i: i.timestamp)
            if seed.crash:
                contributions[origins]['crashes'].add(seed)
            else:
                crashes = origins.transition_set - found
                if not crashes:
                    continue

                contributions['coverages'].update(crashes)
                found |= crashes

        return sorted(
            (
                (k, list(map(len, contributions[k])),)
                for k in contributions.keys()
            ),
            key=lambda x: x[0].timestamp)

    def reload(self, load_crashes):
        self._load_instances()
        for i in self.instances:
            self._load_inputs(i)
            if load_crashes:
                self._load_inputs(i, input_type="crashes")
        self.resolve_sources()
        return self

    def _load_instances(self):
        self.instances = [
            os.path.basename(os.path.dirname(n))
            for n in glob.glob(os.path.join(self._dir, "*", "queue"))
        ]
        self.instance_inputs = {i: {} for i in self.instances}
        self.logger.debug("Instances: %s", self.instances)

    def _load_inputs(self, instance, input_type="queue"):
        self.logger.info("Loading inputs from instance %s", instance)
        for fp in glob.glob(
            os.path.join(self._dir, instance, input_type, "id*")):
            f = os.path.basename(fp)
            self.logger.debug("Adding input %s (type %s)", f, input_type)
            i = Input(f, instance, self)
            self.inputs[i.instance + ':' + i.id] = i
            self.instance_inputs[i.instance][i.id] = i

    def resolve_sources(self):
        for i in self.inputs.values():
            i.resolve_sources()

    def instance_input(self, instance, id_):
        return self.instance_inputs[instance][id_]

    def make_graph(self):
        graph = networkx.DiGraph()
        for child in self.inputs.values():
            for parent in child.sources:
                graph.add_edge(parent, child)
        return graph

    def plot(self, output=None):
        import matplotlib.pyplot as plt
        plt.close()
        networkx.draw(self.make_graph())
        if output:
            plt.savefig(output)
        else:
            plt.show()
