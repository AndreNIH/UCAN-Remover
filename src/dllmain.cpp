#include "pch.h"
#include <vector>
#include <string>
#include <iostream>
#include <fstream>
#include <algorithm>
#include "asciistrings.h"
struct gjl_format {
	size_t hash;
	std::string search_text;
	std::string replace_text;
	std::string level_name;
	friend std::istream& operator>>(std::istream& is, gjl_format& gjl_struct) {
		is >> std::ws;
		is >> gjl_struct.hash;
		is.ignore();
		std::getline(is, gjl_struct.search_text);
		std::getline(is, gjl_struct.replace_text);
		std::getline(is, gjl_struct.level_name);
		return is;
	}
};

class Autorelease {
private:
	void* address = nullptr;
	const std::vector<BYTE>bytes;
public:
	Autorelease(void* aAddress, const std::vector<BYTE>&aBytes) : address(aAddress), bytes(aBytes){}
	~Autorelease() {
		if (address == nullptr) return;
		DWORD oldProtect;
		if(!VirtualProtect(address, bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) throw;
		for (int offset = 0; offset < bytes.size(); offset++) reinterpret_cast<char*>(address)[offset] = bytes[offset]; 
		VirtualProtect(address, bytes.size(), oldProtect, &oldProtect);
	}
};

bool create_jump(void* at, void* to, int size) {
	DWORD previous_protection;
	DWORD dAt(reinterpret_cast<DWORD>(at));
	DWORD dTo(reinterpret_cast<DWORD>(to));
	if (size < 5) return false;
	if (!VirtualProtect(at, size, PAGE_EXECUTE_READWRITE, &previous_protection)) return false;
	DWORD relative_offset = dTo - dAt - 5;
	memset(at, 0xE9, 1);
	memcpy((void*)(dAt + 1), &relative_offset, sizeof(DWORD));
	for (int i = 5; i < size; i++) memset(reinterpret_cast<void*>(dAt + i), 0x90, 1);
	VirtualProtect(at, size, previous_protection, &previous_protection);
	return true;
}

Autorelease write_bytes(void* Address, const std::vector<BYTE>& Bytes) {
	DWORD oldProtect;
	if (!VirtualProtect(Address, Bytes.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) return Autorelease(nullptr, {});
	for (int offset = 0; offset < Bytes.size(); offset++) reinterpret_cast<char*>(Address)[offset] = Bytes[offset];
	VirtualProtect(Address, Bytes.size(), oldProtect, &oldProtect);
	return Autorelease(Address, Bytes);
}

std::vector<gjl_format>gjl_vec;
char* __cdecl get_new_string(char** original) {
	std::string level_string(*original);
	std::hash<std::string>hash_algo;
	size_t level_hash = hash_algo(level_string);
	auto iter = std::find_if(gjl_vec.begin(), gjl_vec.end(), [level_hash](gjl_format arg) {
		return level_hash == arg.hash;
	});
	if (iter == gjl_vec.end()) return *original;
	std::cout << iter->level_name << ": Detected | Performing level string maniulation\n";
	std::string modified_level_string = level_string.replace(level_string.find(iter->search_text),
		iter->replace_text.size(),
		iter->replace_text);
	char* new_level_string = new char[modified_level_string.size() + 1]();
	strcpy_s(new_level_string, modified_level_string.size() + 1, modified_level_string.c_str());
	return new_level_string;
}

DWORD return_address;
_declspec(naked) void detour() {
	_asm {
		mov byte ptr [esp + 0x100] , 0x12
		push ebp
		mov ebp, esp
		push eax
		call get_new_string
		add esp, 4
		pop ebp
		mov[esp + 0xA8], eax
		jmp[return_address]
	}
}


void dll_thread(HMODULE Module) {
	AllocConsole();
	FILE* fp;
	freopen_s(&fp, "CONOUT$", "w", stdout);
	freopen_s(&fp, "CONIN$", "r", stdin);
	std::cout << art::title;
	HMODULE baseAddress = GetModuleHandleA("GeometryDash.exe");
	std::ifstream ifs("levels.gjl");
	if (ifs.is_open()) {
		for (gjl_format level; ifs >> level;) gjl_vec.push_back(level);
		std::cout << "Loaded Levels:\n";
		for (auto& v : gjl_vec)  std::cout << "[*] " << v.level_name << '\n';
		if (baseAddress) {
			DWORD hook_address = reinterpret_cast<DWORD>(baseAddress) + 0x1FC305;
			if (create_jump(reinterpret_cast<void*>(hook_address), detour, 8)) {
				return_address = hook_address + 8;
				Autorelease hook_autorelease(reinterpret_cast<void*>(hook_address), { 0xC6,0x84,0x24,0,1,0,0,0x12 });
				Autorelease anticheat_1 = write_bytes(reinterpret_cast<void*>(hook_address + 0x18B2B4), { 0xB0,1 });
				Autorelease anticheat_2 = write_bytes(reinterpret_cast<void*>(hook_address + 0x1FD557), { 0xEB,0x0C });
				Autorelease anticheat_3 = write_bytes(reinterpret_cast<void*>(hook_address + 0x1FD742), { 0xC7,0x87,0xE0,0x02,0x00,0x00,0x01,0x00,0x00,0x00,0xC7,0x87,0xE4,0x02,0x00,0x00,0x00,0x00,0x00,0x00,0x90,0x90,0x90,0x90,0x90,0x90 });
				Autorelease anticheat_4 = write_bytes(reinterpret_cast<void*>(hook_address + 0x1FD756), { 0x90,0x90,0x90,0x90,0x90,0x90 });
				Autorelease anticheat_5 = write_bytes(reinterpret_cast<void*>(hook_address + 0x1FD79A), { 0x90,0x90,0x90,0x90,0x90,0x90 });
				Autorelease anticheat_6 = write_bytes(reinterpret_cast<void*>(hook_address + 0x1FD7AF), { 0x90,0x90,0x90,0x90,0x90,0x90 });
				std::cout << "Press enter to terminate the program\n\n";
				std::cin.get();

			}else std::cout << "Could not create memory detour\n";
		}else std::cout << "Unable to find process base address\n";
	}else std::cout << "Unable to open \"levels.gjl\"\n";
	
	std::cout << "Program execution complete...\n";
	FreeConsole();
	FreeLibraryAndExitThread(Module, 0);
}


BOOL APIENTRY DllMain( HMODULE hModule,DWORD  ul_reason_for_call,LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
		CreateThread(0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(dll_thread), hModule, 0, 0);
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
