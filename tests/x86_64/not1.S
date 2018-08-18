	.global fail_tests
fail_tests:

	#  Uses lfence
	jne     1f
	mov     0xb0(%r8), %rax
	lfence
	mov     0x30(%rax), %rbx

1:	hlt
