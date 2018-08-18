	.text
	nop

	.global pass_tests	
pass_tests:
	
	# Value pushed onto stack and then popped into another register.
	blt	1f
	ldr	x1, [x2]
	str	x1, [sp, #-8]!
	ldr	x3, [sp], #8
	ldr	s2, [x3]

1:	brk	#6
