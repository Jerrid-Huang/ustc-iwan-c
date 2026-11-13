#include "iwan_nt_trace.h"

#if defined(IWAN_NT_KERNEL)
#include <ntddk.h>

static UNICODE_STRING IwanNtTracePath;
static BOOLEAN IwanNtTraceReady;

VOID IwanNtTrace(_In_ ULONG Stage)
{
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    HANDLE key = NULL;
    ULONG disposition = 0;
    ULONG value = Stage;
    WCHAR letter = L'T';
    WCHAR digits[12];
    ULONG count = 0;

    if (!IwanNtTraceReady) {
        /*
         * Under Control, not under the service key: the loader cannot create
         * Services\iwannt\Parameters while the service is only half installed,
         * and a failed create silently loses the whole trace.
         */
        static const WCHAR path[] =
            L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\IwanNtTrace";
        RtlInitUnicodeString(&IwanNtTracePath, path);
        IwanNtTraceReady = TRUE;
    }

    InitializeObjectAttributes(&attributes, &IwanNtTracePath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateKey(&key, KEY_SET_VALUE, &attributes, 0, NULL,
                                REG_OPTION_NON_VOLATILE, &disposition))) {
        return;
    }

    /* Stage keeps the last step; T<stage> keeps a permanent checklist. */
    RtlInitUnicodeString(&name, L"Stage");
    (void)ZwSetValueKey(key, &name, 0, REG_DWORD, &value, sizeof(value));

    digits[count++] = letter;
    if (Stage >= 100u) {
        digits[count++] = (WCHAR)(L'0' + (Stage / 100u) % 10u);
    }
    if (Stage >= 10u) {
        digits[count++] = (WCHAR)(L'0' + (Stage / 10u) % 10u);
    }
    digits[count++] = (WCHAR)(L'0' + Stage % 10u);
    name.Buffer = digits;
    name.Length = (USHORT)(count * sizeof(WCHAR));
    name.MaximumLength = name.Length;
    (void)ZwSetValueKey(key, &name, 0, REG_DWORD, &value, sizeof(value));

    /*
     * Flush before closing: a bugcheck right after this call would otherwise
     * lose the value, because the hive flushes lazily and the crash is exactly
     * what we are trying to record.
     */
    (void)ZwFlushKey(key);

    ZwClose(key);
}

VOID IwanNtTraceStatus(_In_ ULONG Stage, _In_ ULONG Status)
{
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING name;
    HANDLE key = NULL;
    ULONG disposition = 0;
    ULONG value = Status;
    WCHAR digits[12];
    ULONG count = 0;

    if (!IwanNtTraceReady) {
        IwanNtTrace(Stage);
        return;
    }

    InitializeObjectAttributes(&attributes, &IwanNtTracePath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
    if (!NT_SUCCESS(ZwCreateKey(&key, KEY_SET_VALUE, &attributes, 0, NULL,
                                REG_OPTION_NON_VOLATILE, &disposition))) {
        return;
    }

    /* S<stage> keeps the status of the step that did not return cleanly. */
    digits[count++] = L'S';
    if (Stage >= 100u) {
        digits[count++] = (WCHAR)(L'0' + (Stage / 100u) % 10u);
    }
    if (Stage >= 10u) {
        digits[count++] = (WCHAR)(L'0' + (Stage / 10u) % 10u);
    }
    digits[count++] = (WCHAR)(L'0' + Stage % 10u);
    name.Buffer = digits;
    name.Length = (USHORT)(count * sizeof(WCHAR));
    name.MaximumLength = name.Length;
    (void)ZwSetValueKey(key, &name, 0, REG_DWORD, &value, sizeof(value));
    (void)ZwFlushKey(key);
    ZwClose(key);
}

#else

VOID IwanNtTrace(_In_ ULONG Stage)
{
    (void)Stage;
}

VOID IwanNtTraceStatus(_In_ ULONG Stage, _In_ ULONG Status)
{
    (void)Stage;
    (void)Status;
}

#endif
