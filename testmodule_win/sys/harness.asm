TITLE kfx harness

.code
;void harness(void);
harness PROC
	push rax
	push rbx
	push rcx
	push rdx
	mov rax,13371337h
	cpuid
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret
harness ENDP

;void harness_extended(int magic_mark, unsigned long long address, size_t size);
harness_extended PROC
	push rax
	push rbx
	push rcx
	push rdx
	push rsi

	mov rax,rcx
	mov rsi,rdx
	mov rcx,r8
	cpuid

	pop rsi
	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret
harness_extended ENDP

END
