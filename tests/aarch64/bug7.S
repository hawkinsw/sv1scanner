	.text
	nop

	.global pass_tests	
pass_tests:
	
	# Register pair pushed onto stack and then popped into another register.
	blt	1f
	ldr	x1, [x2]
	stp	x1, x29, [sp, #-32]!
	ldp	x3, x29, [sp], #32
	ldr	s2, [x3]

1:	brk	#6
