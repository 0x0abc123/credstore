#include <windows.h>
#include <wincred.h>
#include <iostream>
#include <string>
#include <vector>
#include <locale>
#include <codecvt>

bool IsConsoleHandle(HANDLE handle) {
    DWORD mode;
    return GetConsoleMode(handle, &mode) != 0;
}

std::wstring ReadConsoleInputW(HANDLE handle) {
    std::wstring input;
    WCHAR buffer[4096];
    DWORD bytesRead;

    ReadConsoleW(handle, buffer, sizeof(buffer) / sizeof(WCHAR), &bytesRead, nullptr);
    input.assign(buffer, bytesRead);

    return input;
}

std::string ReadFileInput(HANDLE handle) {
    std::string input;
    char buffer[4096];
    DWORD bytesRead;

    ReadFile(handle, buffer, sizeof(buffer), &bytesRead, nullptr);
    input.assign(buffer, bytesRead);

    return input;
}


bool StoreCredential(const std::wstring& key, const std::wstring& value) {
    CREDENTIALW credential = {};
    credential.Type = CRED_TYPE_GENERIC;
    credential.TargetName = const_cast<LPWSTR>(key.c_str());
    credential.UserName = const_cast<LPWSTR>(key.c_str());
	std::vector<BYTE> byteData(value.begin(), value.end());
    credential.CredentialBlob = byteData.data();
    credential.CredentialBlobSize = static_cast<DWORD>(byteData.size());
    credential.Persist = CRED_PERSIST_LOCAL_MACHINE;

    return CredWriteW(&credential, 0);
}

std::wstring RetrieveCredential(const std::wstring& key) {
    CREDENTIALW* credential = nullptr;
    if (CredReadW(key.c_str(), CRED_TYPE_GENERIC, 0, &credential)) {
		LPBYTE cbptr = credential->CredentialBlob;
        std::wstring value(cbptr, cbptr+credential->CredentialBlobSize);
        CredFree(credential);
        return value;
    } else {
        return L"Failed to retrieve credential.";
    }
}

std::wstring ReadWStringConsole(const std::wstring& message) {
	HANDLE consoleInputHandle = GetStdHandle(STD_INPUT_HANDLE);
	std::wstring value = L"";
	
	if (IsConsoleHandle(consoleInputHandle)) {
		// Console input, use ReadConsoleW and disable stdin echo to hide secret as it is entered
		DWORD dwMode;
		GetConsoleMode(consoleInputHandle, &dwMode);
        dwMode &= ~ENABLE_ECHO_INPUT;
        SetConsoleMode(consoleInputHandle, dwMode);
		
		std::wcout << message;
		value = ReadConsoleInputW(consoleInputHandle);
		std::wcout << std::endl;

	} else {
		// Non-console input, use ReadFile with UTF-8 handling
		std::wcout << message;
		std::string _userInput = ReadFileInput(consoleInputHandle);
		std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
		value = converter.from_bytes(_userInput);
	}
	return value;
}


int wmain(int argc, wchar_t* argv[]) {
    if (argc < 3) {
        std::wcerr << L"Usage: " << argv[0] << L" <command> <key>\n";
        return 1;
    }

	std::wstring cmd = argv[1];
	std::wstring key = argv[2];

	if(cmd == L"add") {
		std::wstring secret1 = ReadWStringConsole(L"Enter credential secret value: ");
		std::wstring secretConfirm = ReadWStringConsole(L"Confirm secret value: ");
		if(secret1 != secretConfirm) {
			std::wcerr << L"Secret values did not match" << std::endl;
			return 1;
		}
		
		// Store credential
		if (StoreCredential(key, secret1)) {
			std::wcout << L"Credential stored successfully" << std::endl;
			return 0;
		} else {
			std::wcerr << L"Failed to store credential. Error code: " << GetLastError() << std::endl;
			return 1;
		}
	} else if(cmd == L"get") {
		// Retrieve and print credential
		std::wstring retrievedValue = RetrieveCredential(key);
		std::wcout << retrievedValue;
		return 0;
	}
	
    return 1;
}


