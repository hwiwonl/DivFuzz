#!/usr/bin/env python2

from elftools.elf.enums import *
from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_p_flags
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.segments import InterpSegment
from elftools.common.utils import struct_parse
from elftools.construct import Container
from util import *
import sys
import os
import shutil

base_path = os.path.realpath(os.path.dirname(__file__))

usage="""
Binary Patcher for C programmers
bpatch.py [elf file] [trampoline file] [output_path]
in {output_path}, patched binary will have name {[elf file].new}

Trampoline file format:
    Basically it's a C source code, but with additional lines at the end:
    HOOK("library name", [offset to hook], handler)
    HOOK([offset to hook], handler)
    If library name is omitted or "", it will hook main binary.
    Actual hooked address is [library base] + [offset].
    It supports PIE binary.

    SYMHOOK("library name", "function name", handler)
    SYMHOOK("function name", handler)

    Same as above, if library name is omitted, it'll search every library.
    Then the resolved symbol will be same as binary's resolved one.

Trampoline callback:
    The `handler` used above has format:
    void handler(context *ctx) { ... }

    The `context` has registers, and you can get/modify it.
    typedef struct {
        addrint r8, r9, ..., rsp, rip;
    } context;

Example:
    // PC, SP is macro: rip, rsp
    #include <handler.h>

    void fwrite_check(context *ctx) {
        printf("fwrite: %s(%p)", ctx->rdi, ctx->rdi);
        ctx->rax = ctx->rsi * ctx->rdx;
        ctx->PC = *((addrint *)ctx->SP + 1);
    }

    void system_hook(context *ctx) {
        puts("system is not allowed!");
        ctx->PC = 0x41414141;
        return;
    }

    HOOK("", 0x41f420, fwrite_check) // fwrite plt
    SYMHOOK("libc.so", "system", system_hook)
"""

if len(sys.argv) < 4:
    print(usage)
    exit()

path = sys.argv[1]
tramp = sys.argv[2]

# files must be exist
for f in [path, tramp]:
    if not os.path.exists(f):
        print(f + " does not exist")
        exit()

# make output_path if not exists
output_path = sys.argv[3]
try:
    os.makedirs('%s' % output_path)
except:
    pass


def extend_path(_):
    global base_path
    _ = _.replace('$base', base_path)
    _ = _.replace('$', output_path)
    return _

lib_name = extend_path('$/%s' % random_filename())
aligned_lib_name = lib_name
aligned_lib_name += '\x00' * (16 - (len(aligned_lib_name) & 0xf)) + '\x00' * 0xf
new_path = ("%s/%s.afl" % (output_path, os.path.basename(path)))

elffile = open(path, 'rb')
new = bytearray(elffile.read())
elffile.seek(0, 0)
elf = ELFFile(elffile)

# copy assets
def copytree(src, dst):
    os.system('cp -rf "%s" "%s"' % (src, dst))
copytree(extend_path("$base/../assets"), extend_path("$"))

# copy trampoline file
shutil.copy(tramp, extend_path('$/trampoline.c'))

# setup build command
cmd = None

# Normalized architecture names
arch_names = {
        'EM_386': 'i386',
        'EM_X86_64': 'x86_64',
        'EM_ARM': 'arm'
        }

arch = arch_names[elf['e_machine']]

# Compiler. ex: gcc
compiler = None

# Source files. ex: handler.c
# trampoline is included in handler.h
# handler.h includes c file multiple times, and it's called x-macro
sources = ['$/assets/handler.c', '$/trampoline.c']
sources += ['$/assets/sysdeps/' + arch + '/main.s']

# Additional flags. ex: --shared
flags = '-I"%s"' % extend_path('$/assets')
flags += ' --shared -fPIC -Wl,-init,init -ldl'
flags += ' -o"%s"' % lib_name
flags += ' -g' # symbols for debugging

# original loader path in binary
ld_name = None
for segment in elf.iter_segments():
    if isinstance(segment, InterpSegment):
        ld_name = segment.get_interp_name()
        if 'armhf' in ld_name:
            hard_float = True
        break

# If ld_name is still None, it would be a static binary.
# Each architecture should have a fallback ld.so,
# since the trampolines are compiled to a library
# and linked with the target exectuable.

if arch in ('i386', 'x86_64'):
    compiler = 'gcc'
    if arch == 'i386':
        if ld_name is None:
            ld_name = '/lib/ld-linux.so.2'
        flags += ' -m32'
    else:
        if ld_name is None:
            ld_name = '/lib64/ld-linux-x86-64.so.2'
        flags += ' -m64'

elif arch == 'arm':
    print 'ARM is under test! Be careful!'
    ld_name = None
    hard_float = False
    if ld_name is None:
        ld_name = '/lib/ld-linux.so.3'
    if hard_float == True:
        compiler = 'arm-linux-gnueabihf-gcc'
    else:
        compiler = 'arm-linux-gnueabi-gcc'

print 'Compiling trampolines...'
cmd = '%s %s %s' % (compiler, ' '.join(extend_path(_) for _ in sources), flags)
cmd = "cd %s && %s" % (output_path, cmd)
print cmd
if os.system(cmd):
    print 'Compile error!'
    exit()
else:
    print 'Complete!'

segments = []

dynamic = None
for segment in elf.iter_segments():
    if isinstance(segment, DynamicSegment):
        dynamic = segment
        dynamic_header = segment.header
    segments.append(segment.header)

static = None
if dynamic is None:
    print 'No dynamic segments, treating it as static binary'
    static = True
else:
    static = False

tags = []

max_base = 0
min_base = 0xffffffffffffffffffffffffff
for segment in segments:
    if segment.p_type == 'PT_LOAD':
        max_base = max(segment.p_vaddr + segment.p_memsz, max_base)
        min_base = min(segment.p_vaddr, min_base) # for .text
    if segment.p_type == 'PT_PHDR':
        phdr = segment

c = len(new) + 0x1000
c ^= c & 0xfff
not_append = False

# Find offset that satisfies file offset == addr
# It's because of ld.so.
# So hacky..
for i in range(c + min_base, max_base, 0x1000):
    addr = next(elf.address_offsets(i), None)
    if addr is None:
        new_base = i + min_base
        not_append = True
        break

if not_append == False:
    new_base = max_base + 0x1000
    new_base ^= new_base & 0xfff

if new_base - min_base < len(new):
    new_base = len(new) + min_base + 0x1000
    new_base ^= new_base & 0xfff

new = new.ljust(new_base - min_base, "\x00")

Elf_Phdr = elf.structs.Elf_Phdr

new_offset = new_base - min_base
lib_offset = new_offset
seg_offset = len(aligned_lib_name) + 1
tag_offset = (len(segments) + 1) * Elf_Phdr.sizeof() + seg_offset

if not static:
    strtab_ptr, strtab_offset = dynamic.get_table_offset('DT_STRTAB')
    if strtab_offset is None:
        print 'There are no strtab in this file. hmm.. let\'s analyze it!'
        exit()

    for tag in dynamic.iter_tags():
        tags.append(tag.entry)

else:
    # Make strtab, symtab for static binary
    strtab_ptr, strtab_offset = new_base, new_offset
    new_tag = Container(
        d_tag = 'DT_STRTAB',
        d_val = strtab_ptr,
        d_ptr = strtab_offset
    )
    tags.append(new_tag)
    new_tag = Container(
        d_tag = 'DT_SYMTAB',
        d_val = strtab_ptr,
        d_ptr = strtab_offset
    )
    tags.append(new_tag)
    new_tag = Container(
        d_tag = 'DT_NULL',
        d_val = 0,
        d_ptr = 0
    )
    tags.append(new_tag)

# Add library in it
new_tag = Container(
    d_tag='DT_NEEDED',
    d_val=new_offset-strtab_offset,
    d_ptr=new_offset-strtab_offset
)

# Why insert -1? because last entry should be DT_NULL.
tags.insert(-1, new_tag)

tags = ''.join(elf.structs.Elf_Dyn.build(tag) for tag in tags)

ld_path_size = len(ld_name) + 1
memsz = (len(new) & 0xfff) + len(segments) + len(tags) + len(aligned_lib_name) + 1
new_seg = Container(
    p_type = 'PT_LOAD',
    p_flags = 6,
    p_offset = new_offset,
    p_memsz = memsz,
    p_filesz = memsz,
    p_vaddr = new_base,
    p_paddr = new_base,
    p_align = 0x1000,
    )

if static:
    new_seg['p_memsz'] += ld_path_size

segments.append(new_seg)

if static:
    tag_offset += Elf_Phdr.sizeof() * 3
    memsz = len(tags) + Elf_Dyn.sizeof() + 1

    new_seg = Container(
        p_type = 'PT_DYNAMIC',
        p_flags = 6,
        p_offset = new_offset + tag_offset,
        p_memsz = memsz,
        p_filesz = memsz,
        p_vaddr = new_base + tag_offset,
        p_paddr = new_seg['p_vaddr'],
        p_align = 0x4
        )
    segments.append(new_seg)

    new_seg = Container(
        p_type = 'PT_INTERP',
        p_flags = 4,
        p_offset = new_offset + tag_offset + len(tags), # ld.so name is at last
        p_memsz = len(ld_name) + 1,
        p_filesz = new_seg['p_memsz'],
        p_vaddr = new_base + tag_offset + len(tags),
        p_paddr = new_seg['p_vaddr'],
        p_align = 0x1
        )
    segments.insert(0, new_seg)

    new_seg = Container(
        p_type = 'PT_PHDR',
        p_flags = 6,
        p_offset = new_offset + seg_offset,
        p_memsz = len(segments),
        p_filesz = new_seg['p_memsz'],
        p_vaddr = new_base + seg_offset,
        p_paddr = new_seg['p_vaddr'],
        p_align = 0x4
        )
    segments.insert(0, new_seg)
else:
    dynamic_header.p_vaddr = new_base + tag_offset
    dynamic_header.p_paddr = dynamic_header.p_vaddr
    dynamic_header.p_offset = new_offset + tag_offset
    dynamic_header.p_filesz = len(tags)
    dynamic_header.p_memsz = len(tags)
    phdr.p_vaddr = new_base + seg_offset
    phdr.p_paddr = phdr.p_vaddr
    phdr.p_offset = new_offset + seg_offset

segments = map(lambda segment: Elf_Phdr.build(segment), segments)
segments = ''.join(segments)

Elf_Ehdr = elf.structs.Elf_Ehdr
ehdr = elf.header
ehdr['e_phoff'] = new_offset + seg_offset
ehdr['e_phnum'] += 1
if static == True:
    ehdr['e_phnum'] += 3
new[0:Elf_Ehdr.sizeof()] = Elf_Ehdr.build(ehdr)

p  = aligned_lib_name + '\x00'
p += segments
p += tags
new += p
if static:
    new += ld_name
new += '\x00'

new_file = open(new_path, 'wb')
new_file.write(new)
new_file.close()

os.chmod(new_path, 0770)

print('')
print('[*] Done! Locate library at %s' % (lib_name.strip('\x00')))
print('[*] Patched binary is at ' + new_path)
