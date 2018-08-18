	.text
	nop

	.global pass_tests	
pass_tests:

	# Simplest case (variant 1, using a store rather than a load).
	jne     1f			# Speculative instruction.
	mov     0xb0(%rdx), %rax	# First load, using poisoned address register.
	mov     %rbx, 0x30(%rax)	# Store using address from first load.

1:	hlt
