	.text
	nop

	.global pass_tests	
pass_tests:
	
	# A non-involved instruction between the two loads.
	jne     1f
	mov     0xb0(%rdi), %rcx
	mov     0xb0(%rsp), %rax
	nop
	mov     0x30(%rcx), %rbx

1:	hlt
