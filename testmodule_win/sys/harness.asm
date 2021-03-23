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

	mov r9,rdx
	shr rdx,32
	mov r10,rdx

	mov rax,rcx
	mov rcx,r8
	cpuid

	mov rax,r10
	mov rcx,r9
	cpuid

	pop rdx
	pop rcx
	pop rbx
	pop rax
	ret
harness_extended ENDP

END