import string

import angr

__all__ = (
    'extract_strings',
)


def hexescape(s):
    """
    Escape bytes to hexadecimal string
    Args:
        s (bytes): bytes

    Returns:
        str: hexadecimal string
    """

    out = []
    acceptable = (string.ascii_letters + string.digits + ' .').encode()
    for c in s:
        if c not in acceptable:
            out.append("\\x%02x" % c)
        else:
            out.append(chr(c))

    return ''.join(out)


def extract_strings(binary_path, max_length=128):
    p = angr.Project(binary_path, load_options={'auto_load_libs': False})
    cfg = p.analyses.CFG(
        resolve_indirect_jumps=True,
        collect_data_references=True,
    )
    state = p.factory.blank_state()
    string_refs = []

    for addr in cfg.memory_data:
        mem = cfg.memory_data[addr]
        if mem.sort == 'string' and mem.size > 1:
            value = state.solver.eval(
                state.memory.load(mem.address, mem.size),
                cast_to=bytes,
            )
            string_refs.append((addr, value))

    effective_values = set()
    if string_refs:
        for addr, value in string_refs:
            if len(value) <= max_length:
                effective_values.add(value)
            for piece in value.split():
                if len(piece) <= max_length:
                    effective_values.add(piece)

    return map(hexescape, effective_values)
