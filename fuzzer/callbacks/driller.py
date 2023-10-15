import os
import signal
from multiprocessing import Process

from driller.driller import Driller
from fuzzer import Fuzzer
from fuzzer.callbacks.base import CallbackBase

__all__ = (
    'DrillerCallback',
)


class DrillerCallback(CallbackBase):
    def __init__(self,
                 num_workers=1,
                 worker_timeout=10 * 60,
                 length_extension=None):
        super().__init__()
        self.drilled_inputs = set()
        self.num_workers = num_workers
        self.running_drillers = []
        self.worker_timeout = worker_timeout
        self.length_extension = length_extension

    def callback(self, fuzzer: Fuzzer):
        self.running_drillers = [
            driller
            for driller in self.running_drillers
            if driller.is_alive()
        ]
        self.logger.info(
            'The number of running drillers is %d',
            len(self.running_drillers),
        )

        # get the files in queue
        inputs = self.get_queue_inputs(fuzzer)

        # start drilling
        not_drilled = set(inputs) - self.drilled_inputs
        if not not_drilled:
            return

        for input_path in not_drilled:
            if len(self.running_drillers) < self.num_workers:
                break
            self.drilled_inputs.add(input_path)
            proc = Process(
                target=self.start_driller,
                args=(
                    fuzzer.binary_path,
                    input_path,
                    fuzzer.out_dir,
                    self.worker_timeout
                ),
                kwargs={'length_extension': self.length_extension},
            )
            proc.start()
            self.running_drillers.append(proc)

    def kill(self):
        for driller in self.running_drillers:
            driller.terminate()
            os.kill(driller.pid, signal.SIGKILL)

    @staticmethod
    def get_queue_inputs(fuzzer, fuzzer_name='fuzzer-master'):
        """
        Retrieve the current inputs of queue for `fuzzer`

        Returns:
            list: queue input paths
        """

        queue_dir = os.path.join(fuzzer.out_dir, fuzzer_name, 'queue')
        queue_input_paths = []
        for fn in os.listdir(queue_dir):
            if fn == '.state':
                continue
            input_path = os.path.join(queue_dir, fn)
            queue_input_paths.append(input_path)
        return queue_input_paths

    @staticmethod
    def start_driller(binary_path,
                      input_path,
                      out_dir,
                      timeout,
                      length_extension=None):
        driller_inputs = []
        driller_dir = os.path.join(out_dir, 'driller')
        driller_queue_dir = os.path.join(driller_dir, 'queue')
        bitmap_path = os.path.join(out_dir, 'fuzzer-master', 'fuzz_bitmap')

        with open(bitmap_path, 'rb') as f:
            bitmap = f.read()

        os.makedirs(driller_dir, exist_ok=True)
        os.makedirs(driller_queue_dir, exist_ok=True)

        with open(input_path, 'rb') as f:
            driller_inputs.append(f.read())

        if length_extension:
            driller_inputs.append(driller_inputs[0] + '\0' * length_extension)

        signal.alarm(timeout)
        while driller_inputs:
            driller_input = driller_inputs.pop()
            driller = Driller(binary_path, driller_input, bitmap)
            count = 0

            for new_input in driller.drill_generator():
                id_num = len(os.listdir(driller_queue_dir))
                fuzzer_from = (
                    input_path.split('sync/')[1].split('/')[0]
                    + input_path.split('id:')[1].split(',')[0]
                )
                filename = 'id:%06d,from:%s' % (id_num, fuzzer_from)
                path = os.path.join(driller_queue_dir, filename)
                with open(path, 'wb') as f:
                    f.write(new_input[1])
                count += 1

