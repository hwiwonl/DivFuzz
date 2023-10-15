import os
import shutil

from fuzzer import Showmap, Fuzzer
from fuzzer.callbacks.base import CallbackBase

__all__ = (
    'GreaseCallback',
)


class GreaseCallback(CallbackBase):
    def __init__(self,
                 grease_dir,
                 grease_filter=None,
                 grease_sorter=None):
        super().__init__()
        self.grease_dir = grease_dir
        self.grease_filter = (
            grease_filter
            if grease_filter is not None
            else lambda x: True
        )
        self.grease_sorter = (
            grease_sorter
            if grease_sorter is not None
            else lambda x: x
        )

    def callback(self, fuzzer: Fuzzer):
        input_paths = [
            os.path.join(self.grease_dir, fn)
            for fn in os.listdir(self.grease_dir)
            if self.grease_filter(os.path.join(self.grease_dir, fn))
        ]

        if not input_paths:
            return

        # iterate until find one with a new bitmap
        bitmap = fuzzer.bitmap()
        for seed_path in self.grease_sorter(input_paths):
            if os.path.getsize(seed_path) == 0:
                continue

            with open(seed_path) as sf:
                seed = sf.read()

            showmap = Showmap(fuzzer.binary_path, seed)
            shown_map = showmap.showmap()
            for k in shown_map:
                if shown_map[k] > (ord(bitmap[k % len(bitmap)]) ^ 0xff):
                    self.logger.info("Found interesting, syncing to tests")
                    grease_dir = os.path.join(fuzzer.out_dir, "grease")
                    grease_queue_dir = os.path.join(grease_dir, "queue")

                    if not os.path.exists(grease_dir):
                        os.mkdir(grease_dir)
                    if not os.path.exists(grease_queue_dir):
                        os.mkdir(grease_queue_dir)

                    id_num = len(os.listdir(grease_queue_dir))
                    filepath = os.path.join(
                        grease_queue_dir,
                        'id:%06d,grease' % id_num,
                    )
                    shutil.copy(seed_path, filepath)
                    return

        self.logger.info("No interesting inputs found")

    def kill(self):
        """Do nothing"""
        pass
