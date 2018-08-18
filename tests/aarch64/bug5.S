	.text
	nop

	.global pass_tests	
pass_tests:
	
	# Loading into vector/floating point register.
	blt	1f
	ldr	x1, [x2]
	ldr	s2, [x1]

1:	brk	#6
