#include <windows.h>
#include <winevt.h>
#include <iostream>
#include <fstream>
#include <map>
#include <string>
#include <vector>
#include <filesystem>
#include <shellapi.h>
#include <ctime>
#include <thread>
#include <mutex>
#include <json/json.h>
#include <regex>

#pragma comment(lib, "wevtapi.lib")

namespace fs = std::filesystem;
std::mutex logMutex;

// Struct to store event details
struct EventData {
	std::wstring processName;
	std::wstring parentProcessName;
	std::wstring providerName;
	std::wstring eventID;
};

// Function to get the directory of the executable
std::string getExecutablePath() {
	char buffer[MAX_PATH];
	GetModuleFileNameA(nullptr, buffer, MAX_PATH);
	return fs::path(buffer).parent_path().string();
}

// Function to log messages to a file with thread safety
void logMessage(const std::string& message) {
	std::lock_guard<std::mutex> guard(logMutex);
	std::ofstream logFile(getExecutablePath() + "\\log.txt", std::ios::app);
	if (logFile.is_open()) {
		time_t now = time(0);
		struct tm timeInfo;
		char dt[64];

		localtime_s(&timeInfo, &now);
		strftime(dt, sizeof(dt), "%Y-%m-%d %H:%M:%S", &timeInfo);

		std::cout << message << std::endl;
		logFile << "[" << dt << "] " << message << std::endl;
		logFile.close();
	}
}

// Function to export event details to JSON
void exportToJson(const std::wstring& processName, const std::string& eventDetails) {
	std::lock_guard<std::mutex> guard(logMutex);
	std::string jsonFilePath = getExecutablePath() + "\\events.json";

	Json::Value root;
	std::ifstream inFile(jsonFilePath, std::ios::binary);
	if (inFile.is_open()) {
		inFile >> root;
		inFile.close();
	}

	time_t now = time(0);
	struct tm timeInfo;
	char dt[64];

	localtime_s(&timeInfo, &now);
	strftime(dt, sizeof(dt), "%Y-%m-%d %H:%M:%S", &timeInfo);

	Json::Value event;
	event["timestamp"] = dt;
	event["process_name"] = std::string(processName.begin(), processName.end());
	event["details"] = eventDetails;

	root["events"].append(event);

	std::ofstream outFile(jsonFilePath, std::ios::binary);
	if (outFile.is_open()) {
		outFile << root;
		outFile.close();
	}

	//logMessage("Event exported to JSON: " + eventDetails);
}

// Function to elevate privileges and run the program as administrator
void runAsAdmin(const std::wstring& binaryPath) {
	SHELLEXECUTEINFOW sei = { sizeof(SHELLEXECUTEINFOW) };
	sei.lpVerb = L"runas";
	sei.lpFile = binaryPath.c_str();
	sei.nShow = SW_SHOWNORMAL;
	sei.fMask = SEE_MASK_NOCLOSEPROCESS;

	if (!ShellExecuteExW(&sei)) {
		logMessage("Failed to execute process with admin rights. Error: " + std::to_string(GetLastError()));
	}
	else {
		logMessage("Successfully launched process with admin rights.");
		WaitForSingleObject(sei.hProcess, INFINITE);
		CloseHandle(sei.hProcess);
	}
}

// Function to check if a string matches a wildcard pattern
bool wildcardMatch(const std::wstring& pattern, const std::wstring& str) {
	std::wregex regexPattern(L"^" + std::regex_replace(pattern, std::wregex(L"\\*"), L".*") + L"$", std::regex_constants::icase);
	return std::regex_match(str, regexPattern);
}

// Function to load configuration from JSON file
bool loadConfig(std::vector<int>& eventIDs, std::vector<std::wstring>& monitoredProcesses, const std::wstring& binaryPath) {
	std::ifstream configFile(getExecutablePath() + "\\config.json");
	if (!configFile.is_open()) {
		logMessage("Failed to open config.json");
		return false;
	}

	Json::Value config;
	configFile >> config;
	configFile.close();

	for (const auto& id : config["event_ids"]) {
		eventIDs.push_back(id.asInt());
	}

	monitoredProcesses.push_back(binaryPath);

	return true;
}

// Function to extract event XML data
bool extractEventXml(EVT_HANDLE hEvent, std::wstring& xmlData) {
	DWORD bufferSize = 0;
	DWORD bufferUsed = 0;

	if (!EvtRender(nullptr, hEvent, EvtRenderEventXml, 0, nullptr, &bufferSize, &bufferUsed)) {
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			logMessage("Failed to render event. Error: " + std::to_string(GetLastError()));
			return false;
		}
	}

	std::vector<wchar_t> buffer(bufferSize / sizeof(wchar_t));
	if (EvtRender(nullptr, hEvent, EvtRenderEventXml, bufferSize, buffer.data(), &bufferSize, &bufferUsed)) {
		xmlData = std::wstring(buffer.data());
		return true;
	}

	return false;
}

// Function to extract specific data from event XML using regex
bool extractEventData(const std::wstring& eventXml, EventData& eventData) {
	static const std::wregex processNameRegex(L"<Data Name='ProcessName'>(.*?)</Data>");
	static const std::wregex parentProcessNameRegex(L"<Data Name='ParentProcessName'>(.*?)</Data>");
	static const std::wregex providerNameRegex(L"<Provider Name='(.*?)'/>");
	static const std::wregex eventIDRegex(L"<EventID(>(\\d+)|(.*Qualifiers.*([0-9]{4})))</EventID>");

	std::wsmatch match;

	eventData.processName = std::regex_search(eventXml, match, processNameRegex) ? match[1].str() : L"Unknown";
	eventData.parentProcessName = std::regex_search(eventXml, match, parentProcessNameRegex) ? match[1].str() : L"Unknown";
	eventData.providerName = std::regex_search(eventXml, match, providerNameRegex) ? match[1].str() : L"Unknown";
	eventData.eventID = std::regex_search(eventXml, match, eventIDRegex) ? (match[4].str().empty() ? match[2].str() : match[4].str()) : L"Unknown";

	return !(eventData.processName.empty() || eventData.parentProcessName.empty());
}

// Function to process event details and log/export information
void processAndLogEvent(const EventData& eventData, const std::vector<std::wstring>& monitoredProcesses) {
	std::string processNameStr(eventData.processName.begin(), eventData.processName.end());
	std::string providerNameStr(eventData.providerName.begin(), eventData.providerName.end());
	std::string eventIDStr(eventData.eventID.begin(), eventData.eventID.end());

	std::string eventDetails = "ProviderName: " + providerNameStr + " EventID: " + eventIDStr;

	//TODO: filter by eventID from config and processes
	for (const auto& monitoredProcess : monitoredProcesses) {
		if (wildcardMatch(monitoredProcess, eventData.processName)) {
			eventDetails = "Suspicious process: " + processNameStr + " " + eventDetails;
		}
		//logMessage(eventDetails);
		exportToJson(eventData.processName, eventDetails);
	}
}

// Function to monitor events
void monitorEvents(EVT_HANDLE hResults, const std::vector<std::wstring>& monitoredProcesses) {
	EVT_HANDLE hEvent = nullptr;
	DWORD dwReturned = 0;

	while (EvtNext(hResults, 1, &hEvent, 5000, 0, &dwReturned)) {
		std::wstring eventXml;

		if (extractEventXml(hEvent, eventXml)) {
			EventData eventData;
			if (extractEventData(eventXml, eventData)) {
				processAndLogEvent(eventData, monitoredProcesses);
			}
		}

		if (hEvent) {
			EvtClose(hEvent);
			hEvent = nullptr;
		}
	}
}

// Function to monitor events based on config settings
void monitorEventsForBinary(const std::wstring& binaryPath) {
	std::vector<int> eventIDs;
	std::vector<std::wstring> monitoredProcesses;

	if (!loadConfig(eventIDs, monitoredProcesses, binaryPath)) {
		logMessage("Error loading configuration.");
		return;
	}

	std::vector<std::wstring> logs = { L"Application", L"Security", L"System" };

	for (const auto& logName : logs) {
		std::wstring query;

		for (size_t i = 0; i < eventIDs.size(); ++i) {
			query += L"*[System[EventID=" + std::to_wstring(eventIDs[i]) + L"]";
			if (i < eventIDs.size() - 1) {
				query += L"] or ";
			}
		}

		query += L"]";

		EVT_HANDLE hResults = EvtQuery(nullptr, logName.c_str(), query.c_str(), EvtQueryReverseDirection);
		if (!hResults) {
			DWORD error = GetLastError();
			logMessage("Failed to query event log: " + std::to_string(error));
			continue;
		}

		EVT_HANDLE hEvent;
		DWORD dwReturned;

	monitorEvents(hResults, monitoredProcesses);

		EvtClose(hResults);
	}
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		logMessage("Invalid arguments provided. Usage: <binary_to_monitor>");
		return 1;
	}

	std::wstring binaryPath(argv[1], argv[1] + strlen(argv[1]));

	runAsAdmin(binaryPath);

	logMessage("Waiting for events...");

	monitorEventsForBinary(binaryPath);

	logMessage("Monitoring completed.");
	return 0;
}
