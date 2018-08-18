	.global fail_tests
fail_tests:

	# Non-parameter register used.
	blt	1f
	ldr	x1, [x12]
	ldr	x3, [x1]

1:	brk #6

	.data
	.global	foo	
foo:
	.word 1
