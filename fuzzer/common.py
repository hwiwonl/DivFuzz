import os

import angr

__all__ = (
    'set_angr_project',
    'get_angr_project',
    'create_angr_project',
    'get_or_create_angr_project',
)

angr_projects = {}


def set_angr_project(fn, p: angr.Project):
    fn = os.path.basename(fn)
    angr_projects[fn] = p


def get_angr_project(fn) -> angr.Project or None:
    fn = os.path.basename(fn)
    return angr_projects.get(fn)


def create_angr_project(binary_path, *args, **kwargs) -> angr.Project:
    fn = os.path.basename(binary_path)
    p = angr.Project(binary_path, *args, **kwargs)
    angr_projects[fn] = p
    return p


def get_or_create_angr_project(fn, *args, **kwargs):
    p = get_angr_project(fn)
    if p is None:
        return create_angr_project(fn, *args, **kwargs)
