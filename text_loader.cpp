// Compile with:
// cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tctext_loader.cpp /link /OUT:text_loader.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int Error(const char *msg){
    printf("%s (%d)\n", msg, GetLastError());
    return 1;
}

int main(void) {
    // NOP, NOP, Breakpoint, Return
    unsigned char shellcode[] = {0x90, 0x90, 0xcc, 0xc3};
    unsigned int shellcode_len = 4;
    DWORD lpflOldProtect = 0;
    
    void *memory_buf = VirtualAlloc(0, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!memory_buf)
        return Error("Failed to run VirtualAlloc");

    printf("|- Shellcode      -| : 0x%-016p\n", (void *)shellcode);
    printf("|- Memory Buffer  -| : 0x%-016p\n", (void *)memory_buf);

    RtlMoveMemory(memory_buf, shellcode, shellcode_len);

    // Deliberate error to fix here !!!
    BOOL exec_priv = VirtualProtect(memory_buf, shellcode_len, PAGE_EXECUTE_READ, 0);
    if (exec_priv == 0)
        return Error("Failed to run VirtualProtect");

    /* 
    BOOL exec_priv = VirtualProtect(memory_buf, shellcode_len, PAGE_EXECUTE_READ, &lpflOldProtect);

    if (exec_priv == 0)
        return Error("Failed to run VirtualProtect");
    */

    printf("Attach debugger now and search the memory!\n");
    getchar();

    if (exec_priv) {
        HANDLE thread_handle = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)memory_buf, 0, 0, 0);
        WaitForSingleObject(thread_handle, INFINITE);
    }

    return 0;
}
