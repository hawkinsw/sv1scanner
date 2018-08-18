	.global fail_tests
fail_tests:

	# CSDB hint used.
	blt	1f
	ldr	x1, [x2]
	hint	#0x14		// CSDB 
	ldr	s2, [x1]


1:	brk #6

	.data
	.global	foo	
foo:
	.word 1
