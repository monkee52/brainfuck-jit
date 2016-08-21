#include <Windows.h>

#include <conio.h>
#include <stdio.h>

#define halt() __asm { int 3 }

#define BFx86_push_ebp (LPBYTE)"\x55"
#define BFx86_mov_ebp_esp (LPBYTE)"\x8b\xec"
#define BFx86_push_ecx (LPBYTE)"\x51"
#define BFx86_mov_ax_dsParam (LPBYTE)"\x66\xa1"
#define BFx86_mov_dsParam_ax (LPBYTE)"\x66\xa3"
#define BFx86_inc_ax (LPBYTE)"\x66\x40"
#define BFx86_dec_ax (LPBYTE)"\x66\x48"
#define BFx86_add_ax_param (LPBYTE)"\x66\x05"
#define BFx86_sub_ax_param (LPBYTE)"\x66\x2d"
#define BFx86_movzx_ecx_wordPtrDsParam (LPBYTE)"\x0f\xb7\x0d"
#define BFx86_mov_dl_bytePtrEcxParam (LPBYTE)"\x8a\x91"
#define BFx86_mov_bytePtrEcxParam_dl (LPBYTE)"\x88\x91"
#define BFx86_inc_dl (LPBYTE)"\xfe\xc2"
#define BFx86_dec_dl (LPBYTE)"\xfe\xca"
#define BFx86_add_dl_param (LPBYTE)"\x80\xc2"
#define BFx86_sub_dl_param (LPBYTE)"\x80\xea"
#define BFx86_movsx_eax_bytePtrEcxParam (LPBYTE)"\x0f\xbe\x81"
#define BFx86_push_eax (LPBYTE)"\x50"
#define BFx86_call (LPBYTE)"\xe8"
#define BFx86_add_esp_4 (LPBYTE)"\x83\xc4\x04"
#define BFx86_mov_bytePtrEcxParam_al (LPBYTE)"\x88\x81"
#define BFx86_movzx_eax_bytePtrEcxParam (LPBYTE)"\x0f\xb6\x81"
#define BFx86_test_eax_eax (LPBYTE)"\x85\xc0"
#define BFx86_je (LPBYTE)"\x0f\x84"
#define BFx86_xor_eax_eax (LPBYTE)"\x33\xc0"
#define BFx86_mov_esp_ebp (LPBYTE)"\x8b\xe5"
#define BFx86_pop_ebp (LPBYTE)"\x5d"
#define BFx86_ret (LPBYTE)"\xc3"
#define BFx86_jmp (LPBYTE)"\xe9"
#define BFx86_int_3 (LPBYTE)"\xcc"

#define CHUNK_SIZE 4096

typedef void(*bf_void_program)();

struct bf_compiler_opts {
	UINT32 mem_addr;
	UINT32 offset_addr;
	UINT32 putchar_addr;
	UINT32 getchar_addr;
	BOOL optimization;
};

enum bf_type {
	BF_NONE,
	BF_UINT8,
	BF_UINT16,
	BF_UINT32,
	BF_ADDR,
	BF_ADDR_REL
};

DWORD bf_opcode_len(LPBYTE opcode) {
	DWORD ctr = 0;

	while (*(opcode++) != '\0') {
		ctr++;
	}

	return ctr;
}

VOID bf_write(LPBYTE program, DWORD program_max_size, LPDWORD program_len, LPBYTE opcode, enum bf_type param_type, LPVOID param) {
	DWORD opcode_len = bf_opcode_len(opcode);
	DWORD param_size = 0;

	if (param_type == BF_UINT8) {
		param_size = 1;
	} else if (param_type == BF_UINT16) {
		param_size = 2;
	} else if (param_type == BF_UINT32 || param_type == BF_ADDR || param_type == BF_ADDR_REL) {
		param_size = 4;
	}

	if (*program_len + opcode_len + param_size > program_max_size) {
		*program_len += opcode_len + param_size;

		return;
	}

	if (program != NULL) {
		for (DWORD i = 0; i < opcode_len; i++) {
			program[(*program_len)++] = opcode[i];
		}
	} else {
		*program_len += opcode_len;
	}

	if (param_type == BF_UINT8) {
		if (program != NULL) {
			program[(*program_len)++] = (UINT8)((UINT8)param & 0xff);
		} else {
			*program_len += sizeof(UINT8);
		}
	} else if (param_type == BF_UINT16) {
		if (program != NULL) {
			program[(*program_len)++] = (UINT8)((UINT16)param & 0xff);
			program[(*program_len)++] = (UINT8)(((UINT16)param >> 8) & 0xff);
		} else {
			*program_len += sizeof(UINT16);
		}
	} else if (param_type == BF_UINT32 || param_type == BF_ADDR) {
		if (program != NULL) {
			program[(*program_len)++] = (UINT8)((UINT32)param & 0xff);
			program[(*program_len)++] = (UINT8)(((UINT32)param >>  8) & 0xff);
			program[(*program_len)++] = (UINT8)(((UINT32)param >> 16) & 0xff);
			program[(*program_len)++] = (UINT8)(((UINT32)param >> 24) & 0xff);
		} else {
			*program_len += sizeof(UINT32);
		}
	} else if (param_type == BF_ADDR_REL) {
		if (program != NULL) {
			UINT32 param_rel = (UINT32)param - (UINT32)(program + *program_len) - 4;

			program[(*program_len)++] = (UINT8)(param_rel & 0xff);
			program[(*program_len)++] = (UINT8)((param_rel >>  8) & 0xff);
			program[(*program_len)++] = (UINT8)((param_rel >> 16) & 0xff);
			program[(*program_len)++] = (UINT8)((param_rel >> 24) & 0xff);
		} else {
			*program_len += sizeof(UINT32);
		}
	}
}

DWORD bf_compile(struct bf_compiler_opts opts, LPBYTE program, DWORD program_max_size, LPDWORD program_len, LPSTR source, DWORD source_len) {
	UINT32 loop_stack[0x10000] = { 0 };
	UINT16 loop_offset = 0;

	bf_write(program, program_max_size, program_len, BFx86_push_ebp, BF_NONE, NULL); // push ebp
	bf_write(program, program_max_size, program_len, BFx86_mov_ebp_esp, BF_NONE, NULL); // mov ebp, esp
	bf_write(program, program_max_size, program_len, BFx86_push_ecx, BF_NONE, NULL);

	DWORD i = 0;

	while (i < source_len) {
		if (source[i] == '>' || source[i] == '<') {
			if (opts.optimization == TRUE) {
				// Optimise pointer arithmetic
				INT32 ctr = 0;

				while (source[i] == '>' || source[i] == '<') {
					if (source[i] == '>') {
						++ctr;
					} else if (source[i] == '<') {
						--ctr;
					}

					++i;
				}

				--i;

				if (ctr != 0) {
					bf_write(program, program_max_size, program_len, BFx86_mov_ax_dsParam, BF_ADDR, (LPVOID)opts.offset_addr); // mov ax, ds:offset_addr

					if (ctr == 1) {
						bf_write(program, program_max_size, program_len, BFx86_inc_ax, BF_NONE, NULL); // inc ax
					} else if (ctr == -1) {
						bf_write(program, program_max_size, program_len, BFx86_dec_ax, BF_NONE, NULL); // dec ax
					} else if (ctr > 0) {
						bf_write(program, program_max_size, program_len, BFx86_add_ax_param, BF_UINT16, (LPVOID)ctr); // add ax, ctr
					} else if (ctr < 0) {
						bf_write(program, program_max_size, program_len, BFx86_sub_ax_param, BF_UINT16, (LPVOID)(-ctr)); // sub ax, ctr
					}

					bf_write(program, program_max_size, program_len, BFx86_mov_dsParam_ax, BF_ADDR, (LPVOID)opts.offset_addr); // mov ds:offset_addr, ax
				}
			} else {
				bf_write(program, program_max_size, program_len, BFx86_mov_ax_dsParam, BF_ADDR, (LPVOID)opts.offset_addr); // mov ax, ds:offset_addr

				if (source[i] == '>') {
					bf_write(program, program_max_size, program_len, BFx86_inc_ax, BF_NONE, NULL); // inc ax
				} else if (source[i] == '<') {
					bf_write(program, program_max_size, program_len, BFx86_dec_ax, BF_NONE, NULL); // dec ax
				}

				bf_write(program, program_max_size, program_len, BFx86_mov_dsParam_ax, BF_ADDR, (LPVOID)opts.offset_addr); // mov ds:offset_addr, ax
			}
		} else if (source[i] == '+' || source[i] == '-') {
			if (opts.optimization == TRUE) {
				// Optimise data arithmetic
				INT32 ctr = 0;

				while (source[i] == '+' || source[i] == '-') {
					if (source[i] == '+') {
						++ctr;
					} else if (source[i] == '-') {
						--ctr;
					}

					++i;
				}

				--i;

				if (ctr != 0) {
					bf_write(program, program_max_size, program_len, BFx86_movzx_ecx_wordPtrDsParam, BF_ADDR, (LPVOID)opts.offset_addr); // movzx ecx, WORD PTR ds:offset_addr
					bf_write(program, program_max_size, program_len, BFx86_mov_dl_bytePtrEcxParam, BF_ADDR, (LPVOID)opts.mem_addr); // mov dl, BYTE PTR [ecx + param]

					if (ctr == 1) {
						bf_write(program, program_max_size, program_len, BFx86_inc_dl, BF_NONE, NULL);
					} else if (ctr == -1) {
						bf_write(program, program_max_size, program_len, BFx86_dec_dl, BF_NONE, NULL);
					} else if (ctr > 0) {
						bf_write(program, program_max_size, program_len, BFx86_add_dl_param, BF_UINT8, (LPVOID)ctr);
					} else if (ctr < 0) {
						bf_write(program, program_max_size, program_len, BFx86_sub_dl_param, BF_UINT8, (LPVOID)(-ctr));
					}

					bf_write(program, program_max_size, program_len, BFx86_movzx_ecx_wordPtrDsParam, BF_ADDR, (LPVOID)opts.offset_addr); // movzx ecx, WORD PTR ds:offset_addr
					bf_write(program, program_max_size, program_len, BFx86_mov_bytePtrEcxParam_dl, BF_ADDR, (LPVOID)opts.mem_addr); // mov BYTE PTR [ecx + param], dl
				}
			} else {
				bf_write(program, program_max_size, program_len, BFx86_movzx_ecx_wordPtrDsParam, BF_ADDR, (LPVOID)opts.offset_addr); // movzx ecx, WORD PTR ds:offset_addr
				bf_write(program, program_max_size, program_len, BFx86_mov_dl_bytePtrEcxParam, BF_ADDR, (LPVOID)opts.mem_addr); // mov dl, BYTE PTR [ecx + param]

				if (source[i] == '+') {
					bf_write(program, program_max_size, program_len, BFx86_inc_dl, BF_NONE, NULL);
				} else if (source[i] == '-') {
					bf_write(program, program_max_size, program_len, BFx86_dec_dl, BF_NONE, NULL);
				}

				bf_write(program, program_max_size, program_len, BFx86_movzx_ecx_wordPtrDsParam, BF_ADDR, (LPVOID)opts.offset_addr); // movzx ecx, WORD PTR ds:offset_addr
				bf_write(program, program_max_size, program_len, BFx86_mov_bytePtrEcxParam_dl, BF_ADDR, (LPVOID)opts.mem_addr); // mov BYTE PTR [ecx + param], dl
			}
		} else if (source[i] == '.') {
			bf_write(program, program_max_size, program_len, BFx86_movzx_ecx_wordPtrDsParam, BF_ADDR, (LPVOID)opts.offset_addr); // movzx ecx, WORD PTR ds:offset_addr
			bf_write(program, program_max_size, program_len, BFx86_movsx_eax_bytePtrEcxParam, BF_ADDR, (LPVOID)opts.mem_addr); // movsx eax, BYTE PTR [ecx + param]
			bf_write(program, program_max_size, program_len, BFx86_push_eax, BF_NONE, NULL); // push eax
			bf_write(program, program_max_size, program_len, BFx86_call, BF_ADDR_REL, (LPVOID)opts.putchar_addr); // call putchar
			bf_write(program, program_max_size, program_len, BFx86_add_esp_4, BF_NONE, NULL); // add esp, 4
		} else if (source[i] == ',') {
			bf_write(program, program_max_size, program_len, BFx86_call, BF_ADDR_REL, (LPVOID)opts.getchar_addr); // call getchar
			bf_write(program, program_max_size, program_len, BFx86_movzx_ecx_wordPtrDsParam, BF_ADDR, (LPVOID)opts.offset_addr); // movzx ecx, WORD PTR ds:offset_addr
			bf_write(program, program_max_size, program_len, BFx86_mov_bytePtrEcxParam_al, BF_ADDR, (LPVOID)opts.mem_addr); // mov BYTE PTR [ecx + param], al
		} else if (source[i] == '[') {
			loop_stack[loop_offset++] = (UINT32)(program + *program_len); // loop_start:

			bf_write(program, program_max_size, program_len, BFx86_movzx_ecx_wordPtrDsParam, BF_ADDR, (LPVOID)opts.offset_addr); // movzx ecx, WORD PTR ds:offset_addr
			bf_write(program, program_max_size, program_len, BFx86_movzx_eax_bytePtrEcxParam, BF_ADDR, (LPVOID)opts.mem_addr); // movzx eax, BYTE PTR [ecx + param]
			bf_write(program, program_max_size, program_len, BFx86_test_eax_eax, BF_NONE, NULL); // test eax, eax

			bf_write(program, program_max_size, program_len, BFx86_je, BF_ADDR, (LPVOID)0xdeadbeef); // je loop_end

			loop_stack[loop_offset++] = (UINT32)(program + *program_len - 4); // Store address to write address of loop end
		} else if (source[i] == ']') {
			if (loop_offset < 2) {
				return ERROR_STACK_OVERFLOW_READ;
			}

			LPBYTE write_end_addr_at = (LPBYTE)(loop_stack[--loop_offset]);
			UINT32 start_addr = loop_stack[--loop_offset];

			bf_write(program, program_max_size, program_len, BFx86_jmp, BF_ADDR_REL, (LPVOID)start_addr);

			UINT32 end_addr_rel = (UINT32)(program + *program_len) - (UINT32)write_end_addr_at - 4;

			if (program != NULL) {
				*(write_end_addr_at++) = (UINT8)(end_addr_rel & 0xff);
				*(write_end_addr_at++) = (UINT8)((end_addr_rel >>  8) & 0xff);
				*(write_end_addr_at++) = (UINT8)((end_addr_rel >> 16) & 0xff);
				*(write_end_addr_at++) = (UINT8)((end_addr_rel >> 24) & 0xff);
			}
		}

		++i;
	}

	if (loop_offset != 0) {
		return ERROR_STACK_OVERFLOW;
	}

	bf_write(program, program_max_size, program_len, BFx86_xor_eax_eax, BF_NONE, NULL); // xor eax, eax
	bf_write(program, program_max_size, program_len, BFx86_mov_esp_ebp, BF_NONE, NULL); // mov esp, ebp
	bf_write(program, program_max_size, program_len, BFx86_pop_ebp, BF_NONE, NULL); // pop ebp
	bf_write(program, program_max_size, program_len, BFx86_ret, BF_NONE, NULL); // ret

	return NO_ERROR;
}

DWORD bf_readfile(LPSTR filename, LPSTR * buffer, LPDWORD buffer_len) {
	DWORD buffer_alloc_len = 0;

	HANDLE file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

	if (file == INVALID_HANDLE_VALUE) {
		return GetLastError();
	}

	BOOL keep_going = TRUE;
	CHAR tmp_buffer[CHUNK_SIZE];

	while (keep_going) {
		DWORD bytes_read = 0;

		BOOL result = ReadFile(file, tmp_buffer, CHUNK_SIZE, &bytes_read, NULL);

		if (bytes_read == 0) {
			keep_going = FALSE;

			CloseHandle(file);
		}

		if (!result) {
			DWORD err = GetLastError();

			if (err == ERROR_HANDLE_EOF) {
				keep_going = FALSE;

				CloseHandle(file);
			} else {
				CloseHandle(file);

				return err;
			}
		}

		for (DWORD i = 0; i < bytes_read; i++) {
			if (strchr("><+-[],.", tmp_buffer[i]) != NULL) {
				if (*buffer_len >= buffer_alloc_len) {
					LPSTR new_buffer = (LPSTR)realloc(*buffer, buffer_alloc_len + CHUNK_SIZE);

					if (new_buffer == NULL) {
						CloseHandle(file);

						free(*buffer);

						*buffer = NULL;
						*buffer_len = 0;

						buffer_alloc_len = 0;

						return ERROR_OUTOFMEMORY;
					}

					*buffer = new_buffer;

					buffer_alloc_len += CHUNK_SIZE;
				}

				(*buffer)[(*buffer_len)++] = tmp_buffer[i];
			}
		}
	}

	return NO_ERROR;
}

int main(int argc, char * argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file_name>\n", argv[0]);
		return EXIT_FAILURE;
	}
	
	// Read bf file
	LPSTR filename = argv[1];

	//halt();

	LPSTR source = NULL;
	DWORD source_len = 0;

	DWORD err = bf_readfile(filename, &source, &source_len);

	if (err != NO_ERROR) {
		LPSTR err_msg;

		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&err_msg, 0, NULL);

		fprintf(stderr, err_msg);

		return err;
	}

	// Set up compiler
	struct bf_compiler_opts opts;

	UINT8 bf_program_memory[0x10000] = { 0 };
	UINT16 bf_program_offset = 0;

	opts.mem_addr = (UINT32)bf_program_memory;
	opts.offset_addr = (UINT32)&bf_program_offset;

	opts.putchar_addr = (UINT32)&putchar;
	opts.getchar_addr = (UINT32)&getchar;

	opts.optimization = TRUE;
	
	// Allocate memory for program (64 MB max)
	DWORD program_max_size = 0x4000000;
	DWORD program_len = 0;
	LPBYTE program = VirtualAlloc(NULL, program_max_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Compile
	err = bf_compile(opts, program, program_max_size, &program_len, source, source_len);

	// Clean up source code
	free(source);

	source = NULL;
	source_len = 0;

	if (err != NO_ERROR) {
		VirtualFree(program, 0, MEM_RELEASE);

		LPSTR err_msg;

		FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&err_msg, 0, NULL);

		fprintf(stderr, err_msg);

		return err;
	}

	/*
	// Print program
	printf("\n");

	for (DWORD i = 0; i < program_len; i++) {
		printf("%02x ", program[i]);
	}

	printf("\n\n");
	*/

	// Make program executable
	DWORD old_protection;

	VirtualProtect(program, program_max_size, PAGE_EXECUTE_READ, &old_protection);

	bf_void_program program_fn = (bf_void_program)program;

	program_fn();

	// Cleanup
	VirtualProtect(program, program_max_size, old_protection, &old_protection);
	VirtualFree(program, 0, MEM_RELEASE);

	return EXIT_SUCCESS;
}
