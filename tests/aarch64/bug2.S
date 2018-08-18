	.text
	nop

	.global pass_tests	
pass_tests:
	
	# Register size change, plus conditional in between.
	beq	1f
	ldr	w1, [x2]
	ldr	w3, [x2]
	blt	1f
	ldr	w4, [x5]
	ldr	w6, [x3]

1:	brk	#6
