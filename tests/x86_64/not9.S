	.text
	nop
	
	.global fail_tests
fail_tests:

	jne     1f
	mov     0xb0(%rdi), %rcx
	mov     0xb0(%rsp), %rcx	/* A second load overwrites a previous, potential load.  */
	mov     %rbx, 0x30(%rcx)

1:	hlt

