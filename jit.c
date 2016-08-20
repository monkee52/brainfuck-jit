#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <conio.h>
#include <stdint.h>
#include <Windows.h>

struct bf_compiler {
	uint32_t offset_addr;
	uint32_t mem_addr;
	uint32_t putchar_addr;
	uint32_t getchar_addr;
	BOOL optimization;
};

#define WRITE(x) do { if (buffer != NULL && length < max_length - 1) { *(buffer++) = (x); } ++length; } while (0)

#define WRITE_WORD(x) do {\
	if (buffer != NULL && length < max_length - 3) {\
		*(buffer++) = (x) & 0xff;\
		*(buffer++) = ((x) >> 8) & 0xff;\
	}\
	\
	length += 2;\
} while (0)

#define WRITE_DWORD(x) do {\
	if (buffer != NULL && length < max_length - 5) {\
		*(buffer++) = (x) & 0xff;\
		*(buffer++) = ((x) >> 8) & 0xff;\
		*(buffer++) = ((x) >> 16) & 0xff;\
		*(buffer++) = ((x) >> 24) & 0xff;\
	}\
	\
	length += 4;\
} while (0)

#define WRITE_ADDR WRITE_DWORD

	// mov ds:offset_addr, ax
#define MOV_DSOFFSETADDR_AX() do {\
	WRITE(0x66);\
	WRITE(0xa3);\
	\
	WRITE_ADDR(offset_addr);\
} while (0)

// mov ax, ds:offset_addr
#define MOV_AX_DSOFFSETADDR() do {\
	WRITE(0x66);\
	WRITE(0xa1);\
	\
	WRITE_ADDR(offset_addr);\
} while (0)

// inc ax
#define INC_AX() do {\
	WRITE(0x66);\
	WRITE(0x40);\
} while(0)

// dec ax
#define DEC_AX() do {\
	WRITE(0x66);\
	WRITE(0x48);\
} while (0)

// add ax, n
#define ADD_AX(n) do {\
	WRITE(0x66);\
	WRITE(0x05);\
	\
	WRITE_WORD(n);\
} while (0)

// sub ax, n
#define SUB_AX(n) do {\
	WRITE(0x66);\
	WRITE(0x2d);\
	\
	WRITE_WORD(n);\
} while (0)

// movzx ecx, WORD PTR ds:offset_addr
#define MOVZX_ECX_WORDPTRDSOFFSETADDR() do {\
	WRITE(0x0f);\
	WRITE(0xb7);\
	WRITE(0x0d);\
	\
	WRITE_ADDR(offset_addr);\
} while (0)

#define MOV_DL_BYTEPTRECXMEMADDR() do {\
	WRITE(0x8a);\
	WRITE(0x91);\
	\
	WRITE_ADDR(mem_addr);\
} while (0)

// inc dl
#define INC_DL() do {\
	WRITE(0xfe);\
	WRITE(0xc2);\
} while (0)

// dec dl
#define DEC_DL() do {\
	WRITE(0xfe);\
	WRITE(0xca);\
} while (0)

// add dl, n
#define ADD_DL(n) do {\
	WRITE(0x80);\
	WRITE(0xc2);\
	\
	WRITE((n) & 0xff);\
} while (0)

// sub dl, n
#define SUB_DL(n) do {\
	WRITE(0x80);\
	WRITE(0xea);\
	\
	WRITE((n) & 0xff);\
} while (0)

// mov BYTE PTR [ecx+mem_addr], dl
#define MOV_BYTEPTRECXMEMADDR_DL() do {\
	WRITE(0x88);\
	WRITE(0x91);\
	\
	WRITE_ADDR(mem_addr);\
} while (0)

// movsx eax, BYTE PTR [ecx+mem_addr]
#define MOVSX_EAX_BYTEPTRECXMEMADDR() do {\
	WRITE(0x0f);\
	WRITE(0xbe);\
	WRITE(0x81);\
	\
	WRITE_ADDR(mem_addr);\
} while (0)

// movzx eax, BYTE PTR [ecx+mem_addr]
#define MOVZX_EAX_BYTEPTRECXMEMADDR() do {\
	WRITE(0x0f);\
	WRITE(0xb6);\
	WRITE(0x81);\
	\
	WRITE_ADDR(mem_addr);\
} while (0)

// call getchar
#define CALL_GETCHAR() do {\
	WRITE(0xe8);\
	\
	WRITE_ADDR(-((uint32_t)buffer - getchar_addr + 4));\
} while (0)

// mov BYTE PTR [ecx+mem_addr], al
#define MOV_BYTEPTRECXMEMADDR_AL() do {\
	WRITE(0x88);\
	WRITE(0x81);\
	\
	WRITE_ADDR(mem_addr);\
} while (0)

// push eax
#define PUSH_EAX() do {\
	WRITE(0x50);\
} while (0)

// call putchar
#define CALL_PUTCHAR() do {\
	WRITE(0xe8);\
	\
	WRITE_ADDR(-((uint32_t)buffer - putchar_addr + 4));\
} while (0)

// add esp, 4
#define ADD_ESP_4() do {\
	WRITE(0x83);\
	WRITE(0xc4);\
	WRITE(0x04);\
} while (0)

#define TEST_EAX_EAX() do {\
	WRITE(0x85);\
	WRITE(0xc0);\
} while (0)

// push ebp
#define PUSH_EBP() do {\
	WRITE(0x55);\
} while (0)

// mov ebp, esp
#define MOV_EBP_ESP() do {\
	WRITE(0x8b);\
	WRITE(0xec);\
} while (0)

// push ecx
#define PUSH_ECX() do {\
	WRITE(0x51);\
} while (0)

// xor ebx, ebx
#define XOR_EBX_EBX() do {\
	WRITE(0x33);\
	WRITE(0xdb);\
} while (0)

// xor eax, eax
#define XOR_EAX_EAX() do {\
	WRITE(0x33);\
	WRITE(0xc0);\
} while (0)

// mov esp, ebp
#define MOV_ESP_EBP() do {\
	WRITE(0x8b);\
	WRITE(0xe5);\
} while (0)

// pop ebp
#define POP_EBP() do {\
	WRITE(0x5d);\
} while (0)

// ret
#define RET() do {\
	WRITE(0xc3);\
} while (0)

uint32_t bf_compile(uint8_t * buffer, uint32_t max_length, char code[], struct bf_compiler opts) {
	uint32_t buffer_start = (uint32_t)buffer;

	uint32_t offset_addr = opts.offset_addr;
	uint32_t mem_addr = opts.mem_addr;
	uint32_t putchar_addr = opts.putchar_addr;
	uint32_t getchar_addr = opts.getchar_addr;

	uint32_t loop_stack[65536] = { 0 };
	uint16_t loop_offset = 0;

	uint32_t length = 0;
	uint32_t i = 0;

	PUSH_EBP();
	MOV_EBP_ESP();
	PUSH_ECX();

	while (i < strlen(code)) {
		if (code[i] == '>' || code[i] == '<') {
			if (opts.optimization == TRUE) {
				// Optimise pointer operations
				int ctr = 0;

				while (code[i] == '>' || code[i] == '<') {
					if (code[i] == '>') {
						++ctr;
					}
					else if (code[i] == '<') {
						--ctr;
					}

					++i;
				}

				--i;

				// Only write instructions if there is a change
				if (ctr != 0) {
					MOV_AX_DSOFFSETADDR();

					if (ctr == 1) {
						INC_AX();
					}
					else if (ctr == -1) {
						DEC_AX();
					}
					else if (ctr > 0) {
						ADD_AX(ctr);
					}
					else if (ctr < 0) {
						SUB_AX(-ctr);
					}

					MOV_DSOFFSETADDR_AX();
				}
			}
			else {
				MOV_AX_DSOFFSETADDR();

				if (code[i] == '>') {
					INC_AX();
				}
				else if (code[i] == '<') {
					DEC_AX();
				}

				MOV_DSOFFSETADDR_AX();
			}
		} else if (code[i] == '+' || code[i] == '-') {
			if (opts.optimization == TRUE) {
				// Optimise data operations
				int ctr = 0;

				while (code[i] == '+' || code[i] == '-') {
					if (code[i] == '+') {
						++ctr;
					}
					else if (code[i] == '-') {
						--ctr;
					}

					++i;
				}

				--i;

				// Only write instructions if there is a change
				if (ctr != 0) {
					MOVZX_ECX_WORDPTRDSOFFSETADDR();
					MOV_DL_BYTEPTRECXMEMADDR();

					if (ctr == 1) {
						INC_DL();
					}
					else if (ctr == -1) {
						DEC_DL();
					}
					else if (ctr > 0) {
						ADD_DL(ctr);
					}
					else if (ctr < 0) {
						SUB_DL(-ctr);
					}

					MOVZX_ECX_WORDPTRDSOFFSETADDR();
					MOV_BYTEPTRECXMEMADDR_DL();
				}
			}
			else {
				MOVZX_ECX_WORDPTRDSOFFSETADDR();
				MOV_DL_BYTEPTRECXMEMADDR();

				if (code[i] == '+') {
					INC_DL();
				}
				else if (code[i] == '-') {
					DEC_DL();
				}

				MOVZX_ECX_WORDPTRDSOFFSETADDR();
				MOV_BYTEPTRECXMEMADDR_DL();
			}
		} else if (code[i] == '.') {
			MOVZX_ECX_WORDPTRDSOFFSETADDR();
			MOVSX_EAX_BYTEPTRECXMEMADDR();
			PUSH_EAX();
			CALL_PUTCHAR();
			ADD_ESP_4();
		} else if (code[i] == ',') {
			CALL_GETCHAR();
			MOVZX_ECX_WORDPTRDSOFFSETADDR();
			MOV_BYTEPTRECXMEMADDR_AL();
		} else if (code[i] == '[') {
			// loop_start:
			loop_stack[loop_offset++] = (uint32_t)buffer;

			MOVZX_ECX_WORDPTRDSOFFSETADDR();
			MOVZX_EAX_BYTEPTRECXMEMADDR();
			TEST_EAX_EAX();

			// je loop_end
			WRITE(0x0f);
			WRITE(0x84);

			loop_stack[loop_offset++] = (uint32_t)buffer;

			WRITE_ADDR(0x12345678);
		} else if (code[i] == ']') {
			if (loop_offset == 0) {
				fprintf(stderr, "Unmatched ending ]\n");
				exit(EXIT_FAILURE);
			}

			uint8_t * write_end_addr_at = (uint8_t *)(loop_stack[--loop_offset]);
			uint32_t start_addr = loop_stack[--loop_offset];
			
			// jmp loop_start
			WRITE(0xe9);

			uint32_t start_addr_rel = -((int32_t)buffer - (int32_t)start_addr) - 4;

			WRITE_ADDR(start_addr_rel);

			uint32_t end_addr_rel = (uint32_t)buffer - (uint32_t)write_end_addr_at - 4;

			if (buffer != NULL) {
				*(write_end_addr_at + 0) = (end_addr_rel) & 0xff;
				*(write_end_addr_at + 1) = (end_addr_rel >> 8) & 0xff;
				*(write_end_addr_at + 2) = (end_addr_rel >> 16) & 0xff;
				*(write_end_addr_at + 3) = (end_addr_rel >> 24) & 0xff;
			}
		}

		i++;
	}

	if (loop_offset != 0) {
		fprintf(stderr, "Unmatched starting [\n");
		exit(EXIT_FAILURE);
	}

	XOR_EAX_EAX();
	MOV_ESP_EBP();
	POP_EBP();
	RET();

	++length;

	return length;
}

DWORD g_BytesTransferred = 0;

VOID CALLBACK FileIoCompletionRoutine(__in DWORD dwErrorCode, __in DWORD dwNumberOfBytesTransferred, __in LPOVERLAPPED lpOverlapped) {
	g_BytesTransferred = dwNumberOfBytesTransferred;
}

typedef void(*voidFn)();

int main(int argc, char * argv[]) {
	if (argc != 2) {
		fprintf(stderr, "Usage: %s <file_name>\n", argv[0]);
		return EXIT_FAILURE;
	}

	char * filename = argv[1];

	HANDLE hFile = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, NULL);

	if (hFile == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "Unable to open file \"%s\" for reading.\n GetLastError=%#010x\n", filename, GetLastError());
	}

	LARGE_INTEGER fileSize;

	if (GetFileSizeEx(hFile, &fileSize) == FALSE) {
		fprintf(stderr, "Unable to determine size of file.\n GetLastError=%#010x\n", GetLastError());
		CloseHandle(hFile);

		return EXIT_FAILURE;
	}

	char * code = (char *)malloc(fileSize.LowPart + 1);
	OVERLAPPED ol = { 0 };

	if (ReadFileEx(hFile, code, fileSize.LowPart, &ol, FileIoCompletionRoutine) == FALSE) {
		fprintf(stderr, "Unable to read file.\n GetLastError=%#010x\n", GetLastError());
		CloseHandle(hFile);

		return EXIT_FAILURE;
	}

	CloseHandle(hFile);

	code[g_BytesTransferred - 1] = '0';
	
	struct bf_compiler compiler;

	uint8_t mem[65536] = { 0 };
	uint16_t offset = 0;

	compiler.offset_addr = (uint32_t)&offset;
	compiler.mem_addr = (uint32_t)mem;
	compiler.putchar_addr = (uint32_t)&putchar;
	compiler.getchar_addr = (uint32_t)&getchar;
	compiler.optimization = TRUE;

	// Establish code length

	uint32_t code_length = bf_compile(NULL, 0, code, compiler);
	//uint32_t code_length = 0x6400000;

	uint8_t * program = VirtualAlloc(NULL, code_length, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	bf_compile(program, code_length, code, compiler);
	free(code);

	// Make program executable and run
	DWORD oldProtection;

	VirtualProtect(program, code_length, PAGE_EXECUTE_READ, &oldProtection);

	voidFn progex = (voidFn)program;

	progex();

	// Cleanup
	VirtualProtect(program, code_length, oldProtection, &oldProtection);

	VirtualFree(program, 0, MEM_RELEASE);

	return EXIT_SUCCESS;
}
