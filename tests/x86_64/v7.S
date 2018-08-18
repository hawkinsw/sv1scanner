	.text
	nop

	.global pass_tests	
pass_tests:

	# Simplest case (variant 7).
	cmp	%rdx, %rax		# bounds comparison involving poisoned register (%rdx)
	jge	1f			# speculative branch related to the bounds comparison
	mov	%rcx, 0xb0(%rdx)	# Store using poisoned register
	mov	0xb0(%rdx), %rax	# Load from same address

1:	hlt
