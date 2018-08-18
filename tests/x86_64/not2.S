	.global fail_tests
fail_tests:

	# Uses RAX - a non-parameter regiser
	jne     1f
	mov     0xb0(%rax), %rax
	mov     0x30(%rax), %rbx

1:	hlt
