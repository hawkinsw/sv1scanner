	.text
	nop

	.global pass_tests	
pass_tests:
	
	# Out of order loads.
	beq	1f
2:	ldr	w6, [x3]
	ldr	w3, [x2]
	blt	2b

1:	brk	#6
