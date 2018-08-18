	.global fail_tests
fail_tests:

	# Unreachable code.
	b	1f
	beq	1f
	ldr	x11, [x7]
	ldr	x11, [x11]

1:	brk #6

	.data
	.global	foo	
foo:
	.word 1
