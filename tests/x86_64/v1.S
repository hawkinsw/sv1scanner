	.text
	nop

	.global pass_tests	
pass_tests:

	# Simplest case (variant 1).
	jne     1f			# Speculative instruction.
	mov     0xb0(%rdx), %rax	# First load, using poisoned address register.
	mov     0x30(%rax), %rbx	# Second load using address from first load.

1:	hlt

