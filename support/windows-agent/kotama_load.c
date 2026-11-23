/* SPDX-License-Identifier: SySL-1.0
 * Copyright (c) 2026 langyo <sysl.contact@celestia.world>
 *
 * kotama-load: the wine-side payload loader (the Windows counterpart of
 * own-launch). It LoadLibrary's the payload in its own process so the payload's
 * DllMain starts the agent thread, then spawns the target executable.
 *
 * Usage: kotama-load <payload.dll> -- <target.exe> [args...]
 *
 * Exit code: 1 when the payload fails to load, otherwise the child's code.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>

// Join argv[from..] into one quoted command line.
static void join_command(char *out, size_t out_len, int argc, char **argv, int from)
{
    out[0] = 0;
    for(int i = from;i < argc;i++) {
        if(i > from) {
            strncat(out, " ", out_len - strlen(out) - 1);
        }
        strncat(out, "\"", out_len - strlen(out) - 1);
        strncat(out, argv[i], out_len - strlen(out) - 1);
        strncat(out, "\"", out_len - strlen(out) - 1);
    }
}

int main(int argc, char **argv)
{
    if(argc < 4 || strcmp(argv[2], "--") != 0) {
        fprintf(stderr, "usage: kotama-load <payload.dll> -- <target> [args...]\n");
        return 2;
    }

    HMODULE payload = LoadLibraryA(argv[1]);
    if(payload == NULL) {
        fprintf(stderr, "kotama-load: LoadLibrary(%s) failed, err=%lu\n", argv[1],
                (unsigned long)GetLastError());
        return 1;
    }

    char command[8192];
    join_command(command, sizeof(command), argc, argv, 3);

    STARTUPINFOA startup;
    PROCESS_INFORMATION info;
    memset(&startup, 0, sizeof(startup));
    startup.cb = sizeof(startup);
    if(CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &info) == 0) {
        fprintf(stderr, "kotama-load: CreateProcess(%s) failed, err=%lu\n", command,
                (unsigned long)GetLastError());
        return 1;
    }

    WaitForSingleObject(info.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(info.hProcess, &code);
    CloseHandle(info.hThread);
    CloseHandle(info.hProcess);
    return (int)code;
}