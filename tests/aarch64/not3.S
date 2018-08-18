	.global fail_tests
fail_tests:

	# CSDB used.
	blt	1f
	ldr	x1, [x2]
	csdb
	ldr	s2, [x1]

1:	brk #6

	.data
	.global	foo	
foo:
	.word 1
