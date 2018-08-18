	.global fail_tests
fail_tests:

	# FIXME: Stack load not considered for attack vector.
	jne     1f
	mov     0xb0(%rsp), %rax
	mov     %rbx, 0x30(%rax)

1:	hlt
