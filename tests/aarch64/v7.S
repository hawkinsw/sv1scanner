	.text
	nop

	.global pass_tests	
pass_tests:
	
	blt	1f		/* Speculative instruction.  */
	ldr 	x1, [x2]	/* Load using poisoned register.  */
	str 	x3, [x1]	/* Store using result of load.  */

1:	brk	#6
