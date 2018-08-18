	.text
	nop

	.global pass_tests	
pass_tests:
	
	# Explicit memory reference.
	beq	1f
	ldr	x30, [x7]
	ldr	x0, =0x123456789abcde0
	ldr	x30, [x30]

1:	brk	#6
