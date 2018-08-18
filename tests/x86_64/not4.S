	
	.global fail_tests
fail_tests:

	# First instruction is a store rather than load.
	jne     1f
	mov     %rax, 0xb0(%rdx)
	mov     0x30(%rax), %rbx

1:	hlt
