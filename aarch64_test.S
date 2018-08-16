	.text
	nop

	.global pass_tests	
pass_tests:
	# Simple test case.
	blt	1f
	ldr 	x1, [x2]
	ldr 	x3, [x1]

1:	# Value moved between registers.
	beq	1f
	ldr	w1, [x2]
	mov	x11, x1
	ldr	x3, [x11]

1:	# Register size change, plus conditional in between.
	beq	1f
	ldr	w1, [x2]
	ldr	w3, [x2]
	blt	1f
	ldr	w4, [x5]
	ldr	w6, [x3]

1:	# Attack register overwritten by load.
	beq	1f
	ldr	x15, [x4]
	ldr	x15, [x15]

1:	# Explicit memory reference.
	beq	1f
	ldr	x30, [x7]
	ldr	x0, =0x123456789abcde0
	ldr	x30, [x30]

1:	# Loading into vector/floating point register.
	blt	1f
	ldr	x1, [x2]
	ldr	s2, [x1]

1:	# Value pushed onto stack and then popped into another register.
	blt	1f
	ldr	x1, [x2]
	str	x1, [sp, #-8]!
	ldr	x3, [sp], #8
	ldr	s2, [x3]
	
1:	# Register pair pushed onto stack and then popped into another register.
	blt	1f
	ldr	x1, [x2]
	stp	x1, x29, [sp, #-32]!
	ldp	x3, x29, [sp], #32
	ldr	s2, [x3]

1:	# Out of order loads.
	beq	1f
2:	ldr	w6, [x3]
	ldr	w3, [x2]
	blt	2b
	
	.global fail_tests
fail_tests:

1:	# Non-parameter register used.
	blt	1f
	ldr	x1, [x12]
	ldr	x3, [x1]

1:	# CSDB hint used.
	blt	1f
	ldr	x1, [x2]
	hint	#0x14		// CSDB 
	ldr	s2, [x1]

1:	# CSDB used.
	blt	1f
	ldr	x1, [x2]
	csdb
	ldr	s2, [x1]

1:	# Loaded value not used.
	blt	1f
	ldr x2, [x2]
	ldr x3, [x22]

	# First memory access is a store not a load
	blt	1f
	str 	x1, [x2]
	ldr 	x3, [x1]

1:	# Unreachable code.
	b	x2
	beq	1f
	ldr	x11, [x7]
	ldr	x11, [x11]
	
1:	# Processor termination
	brk	#6

	.data
	.global	foo	
foo:
	.word 1
