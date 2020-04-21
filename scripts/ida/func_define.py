import idautils

def flush_ahead(cur, until):
	step = 50
	for i in xrange(cur, until, step):
		if (i + step) <= until:
			del_items()


def go():
	for ea in Segments():
		if SegName(ea) == '.text':
			text_start, text_end = SegStart(ea), SegEnd(ea)

	print '[*] text_start: %#x' % text_start
	print '[*] text_end: %#x' % text_end


	prologue = [85L, 72L, 137L, 229L]
	# addr = text_start
	addr = here()
	# for addr in xrange(test_start, text_end-50):
	while addr <= (text_end - 50):
		cur_bytes = [Byte(addr+i) for i in xrange(4)]
		if len(GetFunctionName(addr)) != 0:
			addr = GetFunctionAttr(addr, FUNCATTR_END)
			# print '[*] Address of current function: %#x' % addr 
		elif cur_bytes == prologue and len(GetFunctionName(addr)) == 0:
			MakeFunction(addr)
			print '[!] Created function at %#x' % addr
			addr = GetFunctionAttr(addr, FUNCATTR_END)
			# print '[*] Address of current function: %#x' % addr 
		else:
			addr += 1
		print '[*] Current address: %#x' % addr 
