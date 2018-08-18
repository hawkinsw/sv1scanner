	.global fail_tests
fail_tests:

	# First memory access is a store not a load
	blt	1f
	str 	x1, [x2]
	ldr 	x3, [x1]

1:	brk #6

	.data
	.global	foo	
foo:
	.word 1
