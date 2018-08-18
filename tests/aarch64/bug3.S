	.text
	nop

	.global pass_tests	
pass_tests:
	
	# Attack register overwritten by load.
	beq	1f
	ldr	x15, [x4]
	ldr	x15, [x15]

1:	brk	#6
