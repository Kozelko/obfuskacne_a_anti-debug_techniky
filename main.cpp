#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <cstring>
#include <fstream>
#include <sstream>

int main();

// 1. COMPILE-TIME XOR OBFUSKÁCIA

template <size_t N, char Key>
class CompileTimeXor
{
public:
    char encrypted[N];

    // constexpr konštruktor - vykoná sa počas kompilácie
    constexpr CompileTimeXor(const char (&str)[N]) : encrypted{}
    {
        for (size_t i = 0; i < N; ++i)
            encrypted[i] = str[i] ^ Key;
    }

    // Dešifrovanie za behu
    std::string decrypt() const
    {
        std::string result;
        result.reserve(N - 1);
        for (size_t i = 0; i < N - 1; ++i)
        {
            volatile char c = encrypted[i] ^ Key;
            result += c;
        }
        return result;
    }
};

// Makro pre jednoduché použitie compile-time XOR
// Použitie: std::string secret = CTXOR("TajnyText", 0x42);
#define CTXOR(str, key) []() { \
    static constexpr CompileTimeXor<sizeof(str), key> x(str); \
    return x.decrypt(); }()

#define XSTR(str, key) CTXOR(str, key)

// 2. RUNTIME XOR OBFUSKÁCIA
// Šifruje dáta ZA BEHU programu

void runtime_xor_encrypt(std::string &data, char key)
{
    for (char &c : data)
        c ^= key;
}

void demonstrate_runtime_xor()
{
    std::string data = "Runtime_Secret_Data";
    char key = 'K';

    std::cout << "\n--- Runtime XOR Demonstracia ---" << std::endl;
    std::cout << "Povodny text: " << data << std::endl;

    // Zašifruj
    runtime_xor_encrypt(data, key);
    std::cout << "Zasifrovany (v pamati): [" << data.size() << " bajtov]" << std::endl;

    // Dešifruj
    runtime_xor_encrypt(data, key);
    std::cout << "Desifrovany: " << data << std::endl;
}

// 3. TIMING CHECK
unsigned long long rdtsc()
{
#if defined(__x86_64__) || defined(_M_X64) || defined(__i386__) || defined(_M_IX86)
    unsigned int lo, hi;
    __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
    return ((unsigned long long)hi << 32) | lo;
#else
    // Fallback pre ARM a ine architektury
    return std::chrono::high_resolution_clock::now().time_since_epoch().count();
#endif
}

bool check_timing()
{
    unsigned long long t1 = rdtsc();

    for (int i = 0; i < 100; i++)
    {
        volatile int x = i * 2;
    }

    unsigned long long t2 = rdtsc();

    if ((t2 - t1) > 10000)
    {
        std::cout << "[DETEKCIA] RDTSC Timing check: Program bezi prilis pomaly!" << std::endl;
        return true;
    }
    return false;
}

// 3. PLATFORM SPECIFIC CHECKS
#ifdef _WIN32
#include <windows.h>
#include <winternl.h>

PPEB get_peb()
{
#if defined(__GNUC__)
    unsigned long long peb_addr;
    __asm__("movq %%gs:0x60, %0" : "=r"(peb_addr));
    return (PPEB)peb_addr;
#else
    return (PPEB)__readgsqword(0x60);
#endif
}

bool check_platform_debug()
{
    bool detected = false;

    std::cout << "\n=== Windows Anti-Debug Kontroly ===" << std::endl;

    // 1. IsDebuggerPresent check
    if (IsDebuggerPresent())
    {
        std::cout << "[DETEKCIA] IsDebuggerPresent() zachytil debugger!" << std::endl;
        detected = true;
    }
    else
    {
        std::cout << "[OK] IsDebuggerPresent() check presiel" << std::endl;
    }

    // 2. PEB->BeingDebugged check
    PPEB pPeb = get_peb();
    if (pPeb && pPeb->BeingDebugged == 1)
    {
        std::cout << "[DETEKCIA] PEB->BeingDebugged flag je nastaveny!" << std::endl;
        detected = true;
    }
    else
    {
        std::cout << "[OK] PEB->BeingDebugged check presiel" << std::endl;
    }

    // 3. CheckRemoteDebuggerPresent check
    BOOL isDebuggerPresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent) && isDebuggerPresent)
    {
        std::cout << "[DETEKCIA] CheckRemoteDebuggerPresent() zachytil debugger!" << std::endl;
        detected = true;
    }
    else
    {
        std::cout << "[OK] CheckRemoteDebuggerPresent() check presiel" << std::endl;
    }

    // 4. NtQueryInformationProcess - ProcessDebugPort
    typedef NTSTATUS(WINAPI * pNtQueryInformationProcess)(
        HANDLE ProcessHandle,
        PROCESSINFOCLASS ProcessInformationClass,
        PVOID ProcessInformation,
        ULONG ProcessInformationLength,
        PULONG ReturnLength);

    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll)
    {
        pNtQueryInformationProcess NtQueryInfoProcess =
            (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (NtQueryInfoProcess)
        {
            DWORD debugPort = 0;
            NTSTATUS status = NtQueryInfoProcess(
                GetCurrentProcess(),
                (PROCESSINFOCLASS)7, // ProcessDebugPort
                &debugPort,
                sizeof(debugPort),
                NULL);

            if (status == 0 && debugPort != 0)
            {
                std::cout << "[DETEKCIA] NtQueryInformationProcess (DebugPort) zachytil debugger!" << std::endl;
                detected = true;
            }
            else
            {
                std::cout << "[OK] NtQueryInformationProcess check presiel" << std::endl;
            }
        }
    }

    // 5. NtQueryInformationProcess - ProcessDebugObjectHandle
    if (hNtdll)
    {
        pNtQueryInformationProcess NtQueryInfoProcess =
            (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");

        if (NtQueryInfoProcess)
        {
            HANDLE debugObject = NULL;
            NTSTATUS status = NtQueryInfoProcess(
                GetCurrentProcess(),
                (PROCESSINFOCLASS)30, // ProcessDebugObjectHandle
                &debugObject,
                sizeof(debugObject),
                NULL);

            if (status == 0 && debugObject != NULL)
            {
                std::cout << "[DETEKCIA] NtQueryInformationProcess (DebugObject) zachytil debugger!" << std::endl;
                CloseHandle(debugObject);
                detected = true;
            }
            else
            {
                std::cout << "[OK] ProcessDebugObjectHandle check presiel" << std::endl;
            }
        }
    }

    std::cout << "====================================\n"
              << std::endl;

    return detected;
}

#else
// LINUX
#include <sys/ptrace.h>
#include <unistd.h>

// LINUX SPECIFIC ANTI-DEBUG TECHNIKY

// 1. Kontrola TracerPid v /proc/self/status
bool check_tracer_pid()
{
    std::ifstream status_file("/proc/self/status");
    if (!status_file.is_open())
    {
        std::cout << "[WARNING] Nemozem otvorit /proc/self/status" << std::endl;
        return false;
    }

    std::string line;
    while (std::getline(status_file, line))
    {
        if (line.find("TracerPid:") != std::string::npos)
        {
            std::istringstream iss(line);
            std::string key;
            int pid;
            iss >> key >> pid;

            if (pid != 0)
            {
                // Skontroluj ci to nie je WSL/systemovy proces (false positive)
                std::string proc_path = "/proc/" + std::to_string(pid) + "/comm";
                std::ifstream comm_file(proc_path);
                std::string tracer_name;

                if (comm_file.is_open())
                {
                    std::getline(comm_file, tracer_name);

                    // Whitelist pre WSL a systemove procesy
                    if (tracer_name.find("init") != std::string::npos ||
                        tracer_name.find("systemd") != std::string::npos ||
                        tracer_name.find("wsl") != std::string::npos ||
                        tracer_name.find("bash") != std::string::npos ||
                        tracer_name.find("sh") != std::string::npos)
                    {
                        std::cout << "[INFO] TracerPid " << pid << " (" << tracer_name
                                  << ") je systemovy proces/shell - ignorujem" << std::endl;
                        return false;
                    }

                    std::cout << "[DETEKCIA] TracerPid je " << pid << " (" << tracer_name
                              << ") - debugger aktivny!" << std::endl;
                }
                else
                {
                    std::cout << "[DETEKCIA] TracerPid je " << pid << " - debugger aktivny!" << std::endl;
                }
                return true;
            }
            break;
        }
    }
    return false;
}

// 2. Kontrola LD_PRELOAD
bool check_ld_preload()
{
    const char *ld_preload = getenv("LD_PRELOAD");
    if (ld_preload != nullptr && strlen(ld_preload) > 0)
    {
        std::cout << "[DETEKCIA] LD_PRELOAD je nastaveny: " << ld_preload << std::endl;
        std::cout << "[DETEKCIA] Mozny pokus o API hooking!" << std::endl;
        return true;
    }
    return false;
}

// 3. Kontrola /proc/self/cmdline na debugger
bool check_cmdline_debugger()
{
    std::ifstream cmdline_file("/proc/self/cmdline");
    if (!cmdline_file.is_open())
    {
        return false;
    }

    std::string cmdline;
    std::getline(cmdline_file, cmdline);

    // Hladame typicke debugger striny
    if (cmdline.find("gdb") != std::string::npos ||
        cmdline.find("lldb") != std::string::npos ||
        cmdline.find("strace") != std::string::npos ||
        cmdline.find("ltrace") != std::string::npos)
    {
        std::cout << "[DETEKCIA] Debugger najdeny v cmdline!" << std::endl;
        return true;
    }
    return false;
}

// 4. Kontrola parent procesu (ci nie je gdb/debugger)
bool check_parent_process()
{
    pid_t ppid = getppid();

    std::string proc_path = "/proc/" + std::to_string(ppid) + "/cmdline";
    std::ifstream parent_cmdline(proc_path);

    if (!parent_cmdline.is_open())
    {
        return false;
    }

    std::string cmdline;
    std::getline(parent_cmdline, cmdline);

    if (cmdline.find("gdb") != std::string::npos ||
        cmdline.find("lldb") != std::string::npos)
    {
        std::cout << "[DETEKCIA] Parent proces je debugger (PID: " << ppid << ")!" << std::endl;
        return true;
    }
    return false;
}

// Hlavna Linux detekcia
bool check_platform_debug()
{
    bool detected = false;

    std::cout << "\n=== Linux Anti-Debug Kontroly ===" << std::endl;

    // 1. Klasicka ptrace kontrola
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0)
    {
        std::cout << "[DETEKCIA] ptrace(PTRACE_TRACEME) zlyhal! Debugger detegovany." << std::endl;
        detected = true;
    }
    else
    {
        std::cout << "[OK] ptrace check presiel" << std::endl;
    }

    // 2. TracerPid kontrola
    if (check_tracer_pid())
    {
        detected = true;
    }
    else
    {
        std::cout << "[OK] TracerPid check presiel" << std::endl;
    }

    // 3. LD_PRELOAD kontrola
    if (check_ld_preload())
    {
        detected = true;
    }
    else
    {
        std::cout << "[OK] LD_PRELOAD check presiel" << std::endl;
    }

    // 4. Cmdline kontrola
    if (check_cmdline_debugger())
    {
        detected = true;
    }
    else
    {
        std::cout << "[OK] Cmdline check presiel" << std::endl;
    }

    // 5. Parent process kontrola
    if (check_parent_process())
    {
        detected = true;
    }
    else
    {
        std::cout << "[OK] Parent process check presiel" << std::endl;
    }

    std::cout << "=================================\n"
              << std::endl;

    return detected;
}
#endif

// bool check_breakpoints()
// {
//     unsigned char *p_code = (unsigned char *)&main;
//     if (*p_code == 0xCC)
//     {
//         std::cout << "[DETEKCIA] Najdeny softverovy breakpoint (0xCC)!" << std::endl;
//         return true;
//     }
//     return false;
// }

// 4. SECURE FLAG PRINTING (Odolné proti 'strings')

// FAKE FLAG
void print_fake_flag()
{
    // Tento flag môže byť v strings, je to len návnada
    std::string fake = XSTR("Flag{NicesTry_But_This_Is_Fake}", 'f');
    std::cout << "\n[SUCCESS] Tajomstvo: " << fake << std::endl;
}

// REAL FLAG - nie je viditeľný cez 'strings'
void print_real_flag()
{
    // Hardcoded XOR array
    // "Flag{Real_Secret_B1T_2025}"
    volatile unsigned char encrypted[] = {
        'F' ^ 0x52, 'l' ^ 0x52, 'a' ^ 0x52, 'g' ^ 0x52, '{' ^ 0x52,
        'R' ^ 0x52, 'e' ^ 0x52, 'a' ^ 0x52, 'l' ^ 0x52, '_' ^ 0x52,
        'S' ^ 0x52, 'e' ^ 0x52, 'c' ^ 0x52, 'r' ^ 0x52, 'e' ^ 0x52,
        't' ^ 0x52, '_' ^ 0x52, 'B' ^ 0x52, '1' ^ 0x52, 'T' ^ 0x52,
        '_' ^ 0x52, '2' ^ 0x52, '0' ^ 0x52, '2' ^ 0x52, '5' ^ 0x52,
        '}' ^ 0x52, '\0' ^ 0x52};

    const unsigned char key = 0x52; // 'R' v hex

    std::cout << "\n[SUCCESS] Tajomstvo: ";

    // Dešifruj a vypíš znak po znaku
    for (size_t i = 0; i < sizeof(encrypted) - 1; i++)
    {
        volatile unsigned char decrypted_char = encrypted[i] ^ key;
        std::cout << (char)decrypted_char;
    }

    std::cout << std::endl;

    // Vymaz pamäť
    memset((void *)encrypted, 0, sizeof(encrypted));
}

// 5. HLAVNÝ PROGRAM
int main()
{
    bool debugger_found = false;

    // 1. Kontrola platformy (teraz s rozšírenými Linux kontrolami)
    if (check_platform_debug())
        debugger_found = true;

    // 2. Kontrola časovania
    if (check_timing())
        debugger_found = true;

    // 3. Kontrola breakpointov
    // if (check_breakpoints())
    //     debugger_found = true;

    std::cout << "Analyza ukoncena. Desifrujem payload..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(1));

    if (debugger_found)
    {
        print_fake_flag();
    }
    else
    {
        print_real_flag();
    }

    // Demonštrácia runtime XOR
    demonstrate_runtime_xor();

    std::cout << "\nProgram ukonceny." << std::endl;
    std::cin.get();
    return 0;
}