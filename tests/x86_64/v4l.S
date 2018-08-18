	.text
	nop

	.global pass_tests	
pass_tests:


	# Simplest case (variant 4/load).
	jne     1f			# Speculative instruction.
	mov	%bx, 0x30(%r8)		# Narrow store, using poisoned address register.
	mov	0x30(%r8), %rcx		# Wider load from same address as the store.
	mov     0x30(%rcx), %rbx	# Load using the result from the wider load.

1:	hlt

