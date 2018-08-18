	.global fail_tests
fail_tests:

	# Loaded value not used.
	blt	1f
	ldr x2, [x2]
	ldr x3, [x22]

1:	brk #6

	.data
	.global	foo	
foo:
	.word 1
