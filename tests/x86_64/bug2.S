	.text
	nop

	.global pass_tests	
pass_tests:

	# Load overwrites destination register.
	jne     1f
	mov     0xb0(%r9), %rcx
	mov     0xb0(%rcx), %rcx

1:	hlt
