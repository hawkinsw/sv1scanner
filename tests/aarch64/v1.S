	.text
	nop

	.global pass_tests	
pass_tests:
	
	# Simple test case (variant 1).
	blt	1f		/* Speculative instruction.  */
	ldr 	x1, [x2]	/* Load using poisoned register.  */
	ldr 	x3, [x1]	/* Second load, using result of first load.  */

1:	brk	#6
