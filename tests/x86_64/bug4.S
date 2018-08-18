	.text
	nop

	.global pass_tests	
pass_tests:

	# Value pushed onto stack and then poped (into a different register).
	jne     1f
	mov     0xb0(%rdx), %rax
	push	%rax
	pop	%rbx
	mov     0x30(%rbx), %rdx

1:	hlt
