	.text
	nop
	
	.global fail_tests
fail_tests:

	jne     1f
	mov     0xb0(%rdx), %rax	# First load, using poisoned address register.
	mov     %rcx, 0xc0(%rdx)	# Store using DIFFERENT address as load.

1:	hlt

