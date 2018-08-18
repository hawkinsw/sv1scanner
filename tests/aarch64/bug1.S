	.text
	nop

	.global pass_tests	
pass_tests:
	
	# Value moved between registers.
	beq	1f
	ldr	w1, [x2]
	mov	x11, x1
	ldr	x3, [x11]

1:	brk	#6
