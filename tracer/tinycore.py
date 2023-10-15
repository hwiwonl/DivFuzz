import struct

__all__ = (
    'TinyCore',
)


class ParseError(Exception):
    pass


class CoreNote(object):
    """This class is used when parsing the NOTES section of a core file.
    """
    __slots__ = (
        'n_type',
        'name',
        'desc',
    )

    N_TYPE_LOOKUP = {
        1: 'NT_PRSTATUS',
        2: 'NT_PRFPREG',
        3: 'NT_PRPSINFO',
        4: 'NT_TASKSTRUCT',
        6: 'NT_AUXV',
        0x53494749: 'NT_SIGINFO',
        0x46494c45: 'NT_FILE',
        0x46e62b7f: 'NT_PRXFPREG'
    }

    def __init__(self, n_type, name, desc):
        self.n_type = CoreNote.N_TYPE_LOOKUP.get(n_type, n_type)
        self.name = name
        self.desc = desc

    def __repr__(self):
        return "<%s %s %s %#x>" % (
            self.__class__.__name__,
            self.name,
            self.n_type,
            len(self.desc),
        )


class TinyCore(object):
    def __init__(self, filename):
        self.filename = filename
        self.notes = []

        # siginfo
        self.si_signo = None
        self.si_code = None
        self.si_errno = None

        # pr_status
        self.pr_cursig = None
        self.pr_sigpend = None
        self.pr_sighold = None

        self.pr_pid = None
        self.pr_ppid = None
        self.pr_pgrp = None
        self.pr_sid = None

        self.pr_utime_usec = None
        self.pr_stime_usec = None
        self.pr_cutime_usec = None
        self.pr_cstime_usec = None

        self.registers = None

        self.pr_fpvalid = None

        self.ph_off = None
        self.ph_num = None

        self.parse()

    def parse(self):
        with open(self.filename, 'rb') as f:
            f.seek(28)
            self.ph_off = struct.unpack('<I', f.read(4))[0]

            f.seek(44)
            self.ph_num = struct.unpack('<I', f.read(4))[0]

            f.seek(self.ph_off)
            ph_headers = f.read(self.ph_num * 0x20)

            for i in range(self.ph_num):
                off = i * 0x20
                p_type_packed = ph_headers[off:off + 4]

                if len(p_type_packed) != 4:
                    continue

                p_type = struct.unpack('<I', p_type_packed)[0]
                if p_type == 4:
                    note_offset_packed = ph_headers[off + 4:off + 8]
                    note_size_packed = ph_headers[off + 16:off + 20]

                    if (len(note_offset_packed) != 4
                        or len(note_size_packed) != 4):
                        continue

                    note_offset = struct.unpack('<I', note_offset_packed)[0]
                    note_size = struct.unpack('<I', note_size_packed)[0]
                    if note_size > 0x100000:
                        note_size = 0x100000

                    f.seek(note_offset)
                    note_data = f.read(note_size)

                    if self.parse_notes(note_data):
                        return

        raise ParseError("Failed to find registers in core")

    def parse_notes(self, note_data):
        """This exists, because note parsing in ELFTools is not good.
        """

        blob = note_data

        note_pos = 0
        while note_pos < len(blob):
            to_unpack = blob[note_pos:note_pos + 12]
            if len(to_unpack) != 12:
                break

            name_sz, desc_sz, n_type = struct.unpack('<3I', to_unpack)
            name_sz_rounded = (((name_sz + (4 - 1)) // 4) * 4)
            desc_sz_rounded = (((desc_sz + (4 - 1)) // 4) * 4)
            n_size = desc_sz_rounded + name_sz_rounded + 12

            # name_sz includes the null byte
            name_pos = note_pos + 12
            name = blob[name_pos:name_pos + name_sz - 1]
            desc_pos = name_pos + name_sz_rounded
            desc = blob[desc_pos:desc_pos + desc_sz]

            self.notes.append(CoreNote(n_type, name, desc))
            note_pos += n_size

        pr_statuses = [x for x in self.notes if x.n_type == 'NT_PRSTATUS']
        if len(pr_statuses) == 0:
            raise ParseError("No pr_status")

        for pr_status in pr_statuses:
            try:
                self.parse_pr_status(pr_status)
            except struct.error:
                continue
            else:
                return True
        return False

    def parse_pr_status(self, pr_status):
        """
         Parse out the pr_status, accumulating the general purpose register
         values. Supports AMD64, X86, ARM, and AARCH64.

         :param pr_status: a note object of type NT_PRSTATUS.
         """
        off = 0

        def unpack(n_member: int, arch_byte: int = 4):
            nonlocal off

            fmt = '<'
            if arch_byte == 4:
                fmt += 'I' * n_member
            elif arch_byte == 8:
                fmt += 'Q' * n_member
            else:
                raise NotImplementedError(
                    '%d bits architecture is not supported' % arch_byte * 8,
                )

            n_read = n_member * arch_byte
            ret = struct.unpack(fmt, pr_status.desc[off:off + n_read])
            off += n_read
            return ret[0] if len(ret) == 1 else ret

        self.si_signo, self.si_code, self.si_errno = unpack(3)
        self.pr_cursig = unpack(1)
        self.pr_sigpend, self.pr_sighold = unpack(2)
        self.pr_pid, self.pr_ppid, self.pr_pgrp, self.pr_sid = unpack(4)
        self.pr_utime_usec = unpack(1) * 1000 + unpack(1)
        self.pr_stime_usec = unpack(1) * 1000 + unpack(1)
        self.pr_cutime_usec = unpack(1) * 1000 + unpack(1)
        self.pr_cstime_usec = unpack(1) * 1000 + unpack(1)

        # parse out general purpose registers
        registers = [
            'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'eax', 'ds', 'es', 'fs',
            'gs', 'xxx', 'eip', 'cs', 'eflags', 'esp', 'ss',
        ]
        for reg in registers:
            value = unpack(1)
            if reg == 'xxx':
                continue

            self.registers[reg] = value

        self.pr_fpvalid = unpack(1)

        return True
