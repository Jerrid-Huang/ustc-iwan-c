#include "iwan_nt_trace.h"

#if defined(IWAN_NT_KERNEL)
#include <ntddk.h>

static UNICODE_STRING IwanNtTracePath;
static BOOLEAN IwanNtTraceReady;

/*
 * The registry values show the last stage but not the order and not how many
 * times a step was attempted, and a lost ZwSetValueKey is indistinguishable
 * from a step that never ran. Appending a line to a file keeps all three.
 */
static VOID
IwanNtTraceAppend(
    _In_ ULONG Stage
    )
{
    static const WCHAR pathText[] = L"\\SystemRoot\\Temp\\iwan-trace.log";
    UNICODE_STRING path;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK status;
    HANDLE file = NULL;
    CHAR line[12];
    CHAR reversed[12];
    ULONG digits = 0;
    ULONG length = 0;
    ULONG value = Stage;

    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return;
    }

    do {
        reversed[digits++] = (CHAR)('0' + (value % 10u));
        value /= 10u;
    } while (value != 0u && digits < sizeof(reversed));
    while (digits > 0u) {
        line[length++] = reversed[--digits];
    }
    line[length++] = '\r';
    line[length++] = '\n';

    RtlInitUnicodeString(&path, pathText);
    InitializeObjectAttributes(&attributes, &path,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);
    {
        NTSTATUS created = ZwCreateFile(&file, FILE_APPEND_DATA | SYNCHRONIZE,
                                        &attributes, &status, NULL,
                                        FILE_ATTRIBUTE_NORMAL,
                                        FILE_SHARE_READ | FILE_SHARE_WRITE,
                                        FILE_OPEN_IF,
                                        FILE_SYNCHRONOUS_IO_NONALERT,
                                        NULL, 0);
        if (!NT_SUCCESS(created)) {
            /*
             * A silent early return here hid the fact that the file channel was
             * never usable, so leave the reason where the registry trace can
             * show it.
             */
            static const WCHAR keyText[] =
                L"\\Registry\\Machine\\System\\CurrentControlSet\\Control\\IwanNtTrace";
            UNICODE_STRING keyPath;
            UNICODE_STRING name;
            HANDLE key = NULL;
            ULONG code = (ULONG)created;
            ULONG ignored = 0;

            RtlInitUnicodeString(&keyPath, keyText);
            InitializeObjectAttributes(&attributes, &keyPath,
                                       OBJ_CASE_INSENSITIVE |
                                       OBJ_KERNEL_HANDLE, NULL, NULL);
            if (NT_SUCCESS(ZwCreateKey(&key, KEY_SET_VALUE, &attributes, 0,
                                       NULL, REG_OPTION_NON_VOLATILE,
                                       &ignored))) {
                RtlInitUnicodeString(&name, L"AppendStatus");
                (void)ZwSetValueKey(key, &name, 0, REG_DWORD, &code,
                                    sizeof(code));
                (void)ZwFlushKey(key);
                ZwClose(key);
            }
            return;
        }
    }
    (void)ZwWriteFile(file, NULL, NULL, NULL, &status, line, length, NULL, NULL);
    ZwClose(file);
}

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

    IwanNtTraceAppend(Stage);

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
