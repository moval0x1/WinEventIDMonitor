#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>

// Function to create a fake event in Windows Event Viewer
void createEvent(WORD eventType, DWORD eventID, const std::string& message) {
    HANDLE hEventLog = RegisterEventSource(NULL, L"FakeEventSource");

    if (hEventLog == NULL) {
        std::cerr << "Error: Unable to register event source. Error code: " << GetLastError() << std::endl;
        return;
    }

    // Convert message to wide string
    std::wstring wMessage(message.begin(), message.end());
    LPCWSTR messages[1] = { wMessage.c_str() };

    if (!ReportEvent(hEventLog, eventType, 0, eventID, NULL, 1, 0, messages, NULL)) {
        std::cerr << "Error reporting event. Error code: " << GetLastError() << std::endl;
    }
    else {
        std::cout << "Event " << eventID << " created: " << message << std::endl;
    }

    DeregisterEventSource(hEventLog);
}

// Function to simulate suspicious events
void generateFakeEvents() {
    std::vector<std::pair<DWORD, std::string>> events = {
        { 4624, "Test Logon Event" },
        { 4688, "Test Process Creation Event" },
        { 4697, "Test Service Installation Event" },
        { 4720, "Test User Account Creation Event" },
        { 1102, "Test Audit Log Cleared Event" }
    };

    for (const auto& event : events) {
        createEvent(EVENTLOG_INFORMATION_TYPE, event.first, event.second);
        Sleep(1000); // Delay between events
    }
}

// Function to spawn a child process to generate additional events
void spawnChildProcess() {
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    std::wstring command = L"cmd.exe /c echo Child Process Event & whoami";

    if (CreateProcess(NULL, &command[0], NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        std::cout << "Child process started: cmd.exe" << std::endl;
        WaitForSingleObject(pi.hProcess, INFINITE); // Wait for child process to complete
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        std::cerr << "Failed to create child process. Error: " << GetLastError() << std::endl;
    }
}

int main() {
    std::cout << "Starting fake event generator..." << std::endl;

    // Generate fake events
    std::thread eventThread(generateFakeEvents);

    // Start the child process
    std::thread childThread(spawnChildProcess);

    eventThread.join();
    childThread.join();

    std::cout << "Fake event generation completed." << std::endl;
    return 0;
}
