import os

__all__ = (
    'core_pattern_check',
    'cpu_frequency_check',
    'child_scheduling_check',
)


def core_pattern_check():
    conf = '/proc/sys/kernel/core_pattern'
    if os.path.exists(conf):
        with open(conf) as f:
            return 'core' in f.read()
    return False


def cpu_frequency_check():
    conf = '/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor'
    if os.path.exists(conf):
        with open(conf) as f:
            return "performance" in f.read()
    return False


def child_scheduling_check():
    conf = '/proc/sys/kernel/sched_child_runs_first'
    if os.path.exists(conf):
        with open(conf) as f:
            return '1' in f.read()
    return False
