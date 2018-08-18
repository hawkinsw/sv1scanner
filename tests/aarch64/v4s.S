	.text
	nop

	.global pass_tests	
pass_tests:
	
	blt	1f		/* Speculative instruction.  */
	str	h1, [x2]	/* Narrow store using poisoned register.  */
	ldr	x1, [x2]	/* Wider load from the same location.  */
	str 	x1, [x1]	/* Second store using result of first load.  */

1:	brk	#6
