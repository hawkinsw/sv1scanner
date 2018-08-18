	.text
	nop

	.global pass_tests	
pass_tests:

	# Value moved between registers before being used for the second time.
	jne     1f
	mov     0xb0(%r9), %rcx
	mov     %rcx, %rax
	mov     0x30(%rax), %rsi

1:	hlt
