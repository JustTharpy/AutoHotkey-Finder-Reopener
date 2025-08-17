#pragma comment(lib, "Version.lib")
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cwctype>
#include <fstream>
#include <thread>
#include <future>
#include <atomic>
#include <mutex>
#include <set>
#include <map>
#include <conio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------
static std::vector<std::wstring> g_ClosedPaths;
static std::atomic<bool> g_Running{ true };

// ---------------------------------------------------------------------------
// Elevation helper
// ---------------------------------------------------------------------------
bool EnsureRunAsAdmin() {
    BOOL isAdmin = FALSE;
    HANDLE token = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        TOKEN_ELEVATION elev{};
        DWORD len = 0;
        if (GetTokenInformation(token, TokenElevation, &elev, sizeof(elev), &len)) {
            isAdmin = elev.TokenIsElevated;
        }
        CloseHandle(token);
    }
    if (isAdmin) return true;

    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(nullptr, exePath, MAX_PATH);
    SHELLEXECUTEINFOW sei{ sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = exePath;
    sei.nShow = SW_SHOWDEFAULT;
    if (ShellExecuteExW(&sei)) return false; // parent exits
    return true;
}

// ---------------------------------------------------------------------------
// Process helpers
// ---------------------------------------------------------------------------
std::wstring PathFromPid(DWORD pid) {
    std::wstring result;
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, FALSE, pid);
    if (!h) return result;
    wchar_t buf[MAX_PATH];
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameW(h, 0, buf, &size)) result.assign(buf, size);
    CloseHandle(h);
    return result;
}

bool KillPidAndRemember(DWORD pid) {
    std::wstring path = PathFromPid(pid);
    if (path.empty()) return false;

    // Never remember Battlefield itself
    std::wstring low = path;
    std::transform(low.begin(), low.end(), low.begin(), ::towlower);
    if (low.find(L"\\battlefield") != std::wstring::npos || low.find(L"\\bf") != std::wstring::npos) {
        // skip
    } else {
        g_ClosedPaths.push_back(path);
        std::wcout << L"Remembered & closed: " << path << std::endl;
    }

    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) return false;
    BOOL ok = TerminateProcess(h, 0);
    CloseHandle(h);
    return !!ok;
}

bool BattlefieldRunning() {
    bool found = false;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32W pe{ sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring name(pe.szExeFile);
            std::wstring low = name;
            std::transform(low.begin(), low.end(), low.begin(), ::towlower);
            if (low.find(L"battlefield") != std::wstring::npos || low.rfind(L"bf", 0) == 0) {
                found = true;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

void MonitorBattlefieldAndRestore() {
    bool last = BattlefieldRunning();
    while (g_Running.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        bool now = BattlefieldRunning();
        if (last && !now) {
            std::wcout << L"Battlefield closed. Restarting remembered programs..." << std::endl;

            std::sort(g_ClosedPaths.begin(), g_ClosedPaths.end());
            g_ClosedPaths.erase(std::unique(g_ClosedPaths.begin(), g_ClosedPaths.end()), g_ClosedPaths.end());

            for (const auto &p : g_ClosedPaths) {
                std::wstring low = p;
                std::transform(low.begin(), low.end(), low.begin(), ::towlower);
                if (low.find(L"\\battlefield") != std::wstring::npos || low.find(L"\\bf") != std::wstring::npos)
                    continue;

                STARTUPINFOW si{ sizeof(si) };
                PROCESS_INFORMATION pi{};
                std::wstring cmd = L"\"" + p + L"\"";
                wchar_t *mutableCmd = cmd.data();
                std::wstring dir = p.substr(0, p.find_last_of(L"\\/"));
                if (CreateProcessW(nullptr, mutableCmd, nullptr, nullptr, FALSE, 0, nullptr,
                                   dir.empty() ? nullptr : dir.c_str(), &si, &pi)) {
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                    std::wcout << L"Restarted " << p << std::endl;
                }
            }
            g_ClosedPaths.clear();
        }
        last = now;
    }
}

// ---------------------------------------------------------------------------
// Main app: list AHK processes, let user close them
// ---------------------------------------------------------------------------
int main() {
    // Elevation
    if (!EnsureRunAsAdmin()) return 0;

    // Start BF monitor
    std::thread bf(MonitorBattlefieldAndRestore);

    std::wcout << L"--- TroubleChute AutoHotkey Finder ---" << std::endl;

    // Enumerate processes
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        std::wcerr << L"Failed to snapshot processes." << std::endl;
        return 1;
    }

    PROCESSENTRY32W pe{ sizeof(pe) };
    int idx = 0;
    std::vector<DWORD> pids;

    if (Process32FirstW(snap, &pe)) {
        do {
            std::wstring exe(pe.szExeFile);
            std::wstring low = exe;
            std::transform(low.begin(), low.end(), low.begin(), ::towlower);

            if (low.find(L"autohotkey") != std::wstring::npos) {
                std::wcout << idx << L": " << exe << L" (PID " << pe.th32ProcessID << L")" << std::endl;
                pids.push_back(pe.th32ProcessID);
                idx++;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (pids.empty()) {
        std::wcout << L"No AutoHotkey processes found." << std::endl;
    } else {
        std::wcout << L"Enter index to close (or -1 to exit): ";
        int choice;
        std::wcin >> choice;
        if (choice >= 0 && choice < (int)pids.size()) {
            if (KillPidAndRemember(pids[choice]))
                std::wcout << L"Process closed." << std::endl;
            else
                std::wcout << L"Failed to close process." << std::endl;
        }
    }

    std::wcout << L"Monitoring Battlefield. Press Ctrl+C to exit." << std::endl;
    while (true) { std::this_thread::sleep_for(std::chrono::seconds(5)); }

    g_Running.store(false);
    if (bf.joinable()) bf.join();
    return 0;
}


// This program scans running processes on the system to detect AutoHotkey executables.
// It does not scan process memory; it examines file version info and binaries on disk.
// Press 'y' and Enter to continue; any other key will exit.
WORD g_defaultConsoleAttributes = 0;

void initDefaultConsoleColor() {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (GetConsoleScreenBufferInfo(hConsole, &csbi)) {
        g_defaultConsoleAttributes = csbi.wAttributes;
    }
}

void setConsoleColor(WORD attributes) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, attributes);
}

class Spinner {
public:
    static constexpr const char* frames = "|/-\\";
    int index = 0;
    char next() {
        char c = frames[index++];
        index %= 4;
        return c;
    }
};

void clearConsoleLine()
{
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hConsole == INVALID_HANDLE_VALUE) return;

    CONSOLE_SCREEN_BUFFER_INFO csbi;
    if (!GetConsoleScreenBufferInfo(hConsole, &csbi)) return;

    COORD cursorPos = csbi.dwCursorPosition;
    cursorPos.X = 0;

    DWORD charsWritten = 0;
    DWORD width = csbi.dwSize.X;

    FillConsoleOutputCharacterW(hConsole, L' ', width, cursorPos, &charsWritten);
    FillConsoleOutputAttribute(hConsole, csbi.wAttributes, width, cursorPos, &charsWritten);

    SetConsoleCursorPosition(hConsole, cursorPos);
}

struct ProcessInfo {
    std::wstring name;
    DWORD pid;
    std::wstring reason;
};

std::atomic<bool> scanning{ true };
std::wstring currentProcess;
std::mutex currentProcessMutex;
std::mutex resultMutex;
std::vector<ProcessInfo> flaggedProcesses;
std::vector<ProcessInfo> unscannableProcesses;

bool containsIgnoreCase(const std::wstring& haystack, const std::wstring& needle) {
    if (needle.empty()) return true;
    for (size_t i = 0; i + needle.size() <= haystack.size(); ++i) {
        size_t j = 0;
        for (; j < needle.size(); ++j) {
            if (towlower(haystack[i + j]) != towlower(needle[j])) break;
        }
        if (j == needle.size()) return true;
    }
    return false;
}

bool loadFile(const std::wstring& path, std::vector<BYTE>& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    std::streamsize sz = f.tellg();
    if (sz <= 0) return false;
    f.seekg(0, std::ios::beg);
    out.resize((size_t)sz);
    return (bool)f.read(reinterpret_cast<char*>(out.data()), sz);
}

bool binaryContainsAHK(const std::vector<BYTE>& data) {
    static const std::string marker = "AutoHotkey";
    size_t n = data.size(), m = marker.size();
    if (n < m) return false;
    for (size_t i = 0; i + m <= n; ++i) {
        size_t j = 0;
        for (; j < m; ++j) {
            if (tolower(data[i + j]) != tolower(marker[j])) break;
        }
        if (j == m) return true;
    }
    return false;
}

bool GetVersionStringValue(const std::wstring& filePath,
    const std::wstring& key,
    std::wstring& outValue)
{
    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);
    if (size == 0) return false;

    std::vector<BYTE> data(size);
    if (!GetFileVersionInfoW(filePath.c_str(), handle, size, data.data()))
        return false;

    struct LANGANDCODEPAGE { WORD wLanguage, wCodePage; } *trans = nullptr;
    UINT transBytes = 0;
    if (!VerQueryValueW(data.data(),
        L"\\VarFileInfo\\Translation",
        reinterpret_cast<void**>(&trans), &transBytes) ||
        transBytes < sizeof(*trans))
    {
        return false;
    }

    wchar_t subBlock[100];
    swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\%s",
        trans->wLanguage, trans->wCodePage, key.c_str());

    LPVOID valuePtr = nullptr;
    UINT valueLen = 0;
    if (!VerQueryValueW(data.data(), subBlock, &valuePtr, &valueLen) || valueLen == 0)
        return false;

    outValue.assign(static_cast<wchar_t*>(valuePtr), valueLen);
    return true;
}

bool terminateProcess(DWORD pid, const std::wstring& name) {
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProcess) {
        std::wcout << L"Failed to open process " << name << L" (PID " << pid << L") for termination.\n";
        return false;
    }

    BOOL result = TerminateProcess(hProcess, 1);
    CloseHandle(hProcess);

    if (result) {
        std::wcout << L"Successfully terminated " << name << L" (PID " << pid << L")\n";
        return true;
    }
    else {
        std::wcout << L"Failed to terminate " << name << L" (PID " << pid << L")\n";
        return false;
    }
}

void scanProcess(const PROCESSENTRY32W& pe, DWORD selfPid) {
    DWORD pid = pe.th32ProcessID;
    if (pid == selfPid) {
        return;
    }
    std::wstring name = pe.szExeFile;

    {
        std::lock_guard<std::mutex> lk(currentProcessMutex);
        currentProcess = name;
    }

    if (containsIgnoreCase(name, L"autohotkey.exe") ||
        containsIgnoreCase(name, L"autohotkeyu64.exe"))
    {
        std::lock_guard<std::mutex> lk(resultMutex);
        flaggedProcesses.push_back({ name, pid, L"Native AutoHotkey executable" });
        return;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        std::lock_guard<std::mutex> lk(resultMutex);
        unscannableProcesses.push_back({ name, pid, L"Cannot open process" });
        return;
    }

    wchar_t buf[MAX_PATH];
    DWORD len = _countof(buf);
    if (!QueryFullProcessImageNameW(hProc, 0, buf, &len)) {
        CloseHandle(hProc);
        std::lock_guard<std::mutex> lk(resultMutex);
        unscannableProcesses.push_back({ name, pid, L"Path query failed" });
        return;
    }
    std::wstring path = buf;
    CloseHandle(hProc);

    std::wstring comp, desc;
    if ((GetVersionStringValue(path, L"CompanyName", comp) &&
        containsIgnoreCase(comp, L"autohotkey")) ||
        (GetVersionStringValue(path, L"FileDescription", desc) &&
            containsIgnoreCase(desc, L"autohotkey")))
    {
        std::lock_guard<std::mutex> lk(resultMutex);
        flaggedProcesses.push_back({ name, pid, L"Version info contains AutoHotkey" });
        return;
    }

    std::vector<BYTE> data;
    if (loadFile(path, data) && binaryContainsAHK(data)) {
        std::lock_guard<std::mutex> lk(resultMutex);
        flaggedProcesses.push_back({ name, pid, L"Binary scan detected AutoHotkey" });
    }
}

int wmain() {
    initDefaultConsoleColor();
    setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"Welcome to the TroubleChute AHK Finder.\n";
    setConsoleColor(g_defaultConsoleAttributes);
    std::wcout << L"This script is provided AS-IS without warranty of any kind. See https://tc.ht/privacy & https://tc.ht/terms.\n";
    std::wcout << L"Find the source code at https://github.com/TCNOco/AutoHotkey-Finder\n\n";

    setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"This program scans running processes on the system to detect AutoHotkey executables.\n";
    std::wcout << L"It does not scan process memory; it examines file version info and binaries on disk.\n\n";
    std::wcout << L"While it should not trigger anticheats, please make sure all games with anticheats are closed before continuing!\n\n";
    setConsoleColor(g_defaultConsoleAttributes);
    std::wcout << L"Press 'y' to continue scanning, any other key to exit: ";
    wchar_t ch = _getwch();
    std::wcout << ch << L"\n"; // Echo the character for user feedback
    if (ch != L'y' && ch != L'Y') {
        return 0;
    }

    Spinner spinner;
    DWORD selfPid = GetCurrentProcessId();

    std::thread spinThread([&]() {
        while (scanning) {
            char frame = spinner.next();
            std::wstring nameCopy;
            {
                std::lock_guard<std::mutex> lk(currentProcessMutex);
                nameCopy = currentProcess;
            }
            clearConsoleLine();
            std::wcout << L"Scanning processes... " << frame << L" " << nameCopy;
            std::wcout.flush();
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        clearConsoleLine();
        std::wcout << L"Scanning processes... done.\n";
        });

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) {
        scanning = false;
        spinThread.join();
        std::cerr << "Error: could not snapshot processes.\n";
        return 1;
    }

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (!Process32FirstW(hSnap, &pe)) {
        CloseHandle(hSnap);
        scanning = false;
        spinThread.join();
        std::cerr << "Error: failed to enumerate processes.\n";
        return 1;
    }

    std::vector<PROCESSENTRY32W> processes;
    do {
        processes.push_back(pe);
    } while (Process32NextW(hSnap, &pe));
    CloseHandle(hSnap);

    std::vector<std::future<void>> futures;
    futures.reserve(processes.size());
    for (auto& p : processes) {
        futures.emplace_back(std::async(std::launch::async, scanProcess, p, selfPid));
    }
    for (auto& f : futures) {
        f.get();
    }

    scanning = false;
    spinThread.join();

    std::wcout << L"\n";

    if (!unscannableProcesses.empty()) {
        std::wcout << L"Processes that could not be scanned: ";
        bool first = true;
        for (const auto& proc : unscannableProcesses) {
            if (!first) std::wcout << L", ";
            std::wcout << proc.name << L" (PID " << proc.pid << L")";
            first = false;
        }
        std::wcout << L"\n\n\n";
        setConsoleColor(FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"Please run this program as Administrator to better search programs\n\n";
        setConsoleColor(g_defaultConsoleAttributes);
    }

    if (flaggedProcesses.empty()) {
        setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
        std::wcout << L"No AutoHotkey processes detected.\n";
        setConsoleColor(g_defaultConsoleAttributes);
        std::wcout << L"Press Enter to exit...";
        std::wcin.get();
        return 0;
    }

    setConsoleColor(FOREGROUND_RED | FOREGROUND_INTENSITY);
    std::wcout << L"AutoHotkey processes detected:\n";
    for (size_t i = 0; i < flaggedProcesses.size(); ++i) {
        const auto& proc = flaggedProcesses[i];
        std::wcout << L" " << (i + 1) << L". " << proc.name << L" (PID " << proc.pid << L") [" << proc.reason << L"]\n";
    }
    setConsoleColor(g_defaultConsoleAttributes);

    std::wcout << L"\nOptions:\n";
    std::wcout << L" 0. Kill all AutoHotkey processes\n";
    std::wcout << L" 1-" << flaggedProcesses.size() << L". Kill specific process\n";
    std::wcout << L" Any other key: Exit without killing\n";
    setConsoleColor(FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    std::wcout << L"\nEnter your choice: ";
    setConsoleColor(g_defaultConsoleAttributes);

    std::wstring input;
    std::getline(std::wcin, input);

    if (input.empty()) {
        std::wcout << L"No selection made. Exiting...\n";
        return 0;
    }

    try {
        int choice = std::stoi(input);
        if (choice == 0) {
            std::wcout << L"\nAttempting to kill all AutoHotkey processes...\n";
            int killed = 0;
            for (const auto& proc : flaggedProcesses) {
                if (terminateProcess(proc.pid, proc.name)) {
                    killed++;
                }
            }
            std::wcout << L"\nSummary: " << killed << L" out of " << flaggedProcesses.size() << L" processes terminated.\n";
        }
        else if (choice >= 1 && choice <= static_cast<int>(flaggedProcesses.size())) {
            const auto& proc = flaggedProcesses[choice - 1];
            std::wcout << L"\nAttempting to kill " << proc.name << L" (PID " << proc.pid << L")...\n";
            terminateProcess(proc.pid, proc.name);
        }
        else {
            std::wcout << L"Invalid choice. Exiting...\n";
        }
    }
    catch (...) {
        std::wcout << L"Invalid input. Exiting...\n";
    }

    std::wcout << L"Press Enter to exit...";
    std::wcin.get();
    return 0;
}
