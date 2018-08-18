	.text
	nop

	.global pass_tests	
pass_tests:


	# Simplest case (variant 4/store).
	jne     1f			# Speculative instruction.
	mov	%bx, 0x30(%r8)		# First store.
	mov	0x30(%r8), %rcx		# Wider load from same address as the store.
	mov     %rbx, 0x30(%rcx)	# Store using address from wider load.

1:	hlt

