from subprocess import *
from elftools.elf.dynamic import DynamicSegment
from elftools.elf.descriptions import describe_p_type, describe_p_flags, describe_e_type
from elftools.common.utils import struct_parse
from elftools.construct import Container
import random
import string
import os

def output(cmd):
	pid = Popen(cmd, shell=True, stdout=PIPE)
	print cmd
	text = pid.stdout.read()
	pid.wait()
	return text

def check_hex(number):
	h = hex(number)
	if h[-1] == 'L':
		h = h[:-1]
	return h

def random_addr(elf):
	base = 0
	size = 0
	for segment in elf.iter_segments():
		p_type = describe_p_type(segment['p_type'])
		if p_type == 'LOAD':
			p_vaddr = segment['p_vaddr']
			p_memsz = segment['p_memsz']
			if p_vaddr > base:
				base = p_vaddr
				size = p_memsz
				if size & 0xfff:
					size = (size & 0xfffffffffffff000) + 0x1000
				else:
					size = size & 0xfffffffffffff000
	if base == 0:
		exit('Base error')
	if elf.elfclass == 32:
		r = random.randint(base + 0x10000, 0x10000000) & 0xfffff000 # for kernel split
	else:
		r = random.randint(base + 0x10000, 0x1000000000000000) & 0xfffffffffffff000 # for kernel split
	r = 0x804f000
	print hex(r)
	return r

def random_filename():
	return ''.join(random.sample(string.lowercase, 10))

def library_add(elf, elffile, lib_name):
	elffile.seek(0, 0)
	new = bytearray(elffile.read())
	elffile.seek(0, 0)

	segments = []

	dynamic = None
	for segment in elf.iter_segments():
		if isinstance(segment, DynamicSegment):
			dynamic = segment
			dynamic_header = segment.header
		segments.append(segment.header)

	if dynamic is None:
		print 'There are no dynamic segments in this file. Is it static?'
		exit()

	strtab_ptr, strtab_offset = dynamic.get_table_offset('DT_STRTAB')
	if strtab_offset is None:
		print 'There are no strtab in this file. hmm.. let\'s analyze it!'
		exit()

	max_base = 0
	min_base = 0xffffffffffffffffffffffffff
	for segment in segments:
		#print segment
		if segment.p_type == 'PT_LOAD':
			max_base = max(segment.p_vaddr + segment.p_memsz, max_base)
			min_base = min(segment.p_vaddr, min_base) # for .text
		if segment.p_type == 'PT_LOAD' and \
		   segment.p_offset < strtab_offset and \
		   segment.p_offset + segment.p_filesz > strtab_offset:
			pass
		if segment.p_type == 'PT_PHDR':
			phdr = segment

	new_base = max_base + 0x1000
	new_base ^= new_base & 0xfff
	new = new.ljust(new_base - min_base, "\x00")

	tags = []
	for tag in dynamic.iter_tags():
		tags.append(tag.entry)

	Elf_Dyn = elf.structs.Elf_Dyn
	new_tag = Container(
		d_tag='DT_NEEDED',
		d_val=len(new)-strtab_offset,
		d_ptr=len(new)-strtab_offset
	)

	tags = tags[:-1] + [new_tag] + [tags[-1]]

	for i in range(len(tags)):
		tag = tags[i]
		tags[i] = Elf_Dyn.build(tag)

	tags = ''.join(tags)

	Elf_Phdr = elf.structs.Elf_Phdr
	new_seg = Container()
	new_seg['p_offset'] = len(new) ^ (len(new) & 0xfff)
	new_seg['p_memsz'] = (len(new) & 0xfff) + len(segments) + len(tags) + len(lib_name)
	new_seg['p_filesz'] = new_seg['p_memsz']
	new_seg['p_type'] = 'PT_LOAD'
	new_seg['p_flags'] = 6
	new_seg['p_vaddr'] = new_base
	new_seg['p_paddr'] = new_seg['p_vaddr']
	new_seg['p_align'] = 0x1000
	segments.append(new_seg)

	dynamic_header.p_vaddr = new_base + Elf_Phdr.sizeof() * len(segments) + len(lib_name) + 1
	dynamic_header.p_paddr = dynamic_header.p_vaddr
	dynamic_header.p_offset = len(new) + len(lib_name) + 1 + Elf_Phdr.sizeof() * len(segments)
	dynamic_header.p_filesz = len(tags)
	dynamic_header.p_memsz = len(tags)

	phdr.p_vaddr = new_base + len(lib_name) + 1
	phdr.p_paddr = phdr.p_vaddr
	phdr.p_offset = len(new) + len(lib_name) + 1

	segments = map(lambda segment: Elf_Phdr.build(segment), segments)
	segments = ''.join(segments)

	Elf_Ehdr = elf.structs.Elf_Ehdr
	ehdr = elf.header
	ehdr['e_phoff'] = len(new) + len(lib_name) + 1
	ehdr['e_phnum'] += 1
	new[0:Elf_Ehdr.sizeof()] = Elf_Ehdr.build(ehdr)

	new += lib_name + '\x00'
	new += segments
	new += tags + '\x00'
	
	return new

py_dir = os.path.dirname(os.path.abspath(__file__)) + '/'
