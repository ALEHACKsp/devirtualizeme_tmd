#include "pch.h"

#include "process_stream.hpp"
#include <Windows.h>
#include <Psapi.h>

process_stream::process_stream(bool x86_64) : x86_stream(x86_64)
{
	this->m_pid = 0;
	this->m_handle = NULL;
}
process_stream::~process_stream()
{
	this->close();
}

bool process_stream::is_open() const
{
	return this->m_handle != NULL;
}
void process_stream::close()
{
	if (this->m_handle != NULL)
	{
		CloseHandle(this->m_handle);
		this->m_handle = NULL;
	}
}

uint32_t process_stream::read(void* buf, uint32_t size)
{
	if (!this->is_open())
		throw std::runtime_error("process is not open");

	LPCVOID address = reinterpret_cast<LPCVOID>(this->m_pos);
	SIZE_T read_bytes = 0;
	if (!ReadProcessMemory(this->m_handle, address, buf, size, &read_bytes))
	{
		DWORD last_error = GetLastError();
		std::stringstream ss;
		ss << "ReadProcessMemory(" << address << ") failed, GLE: " << last_error;
		throw std::runtime_error(ss.str());
	}

	this->m_pos += read_bytes;
	return read_bytes;
}
uint32_t process_stream::write(const void* buf, uint32_t size)
{
	if (!this->is_open())
		throw std::runtime_error("process is not open");

	LPVOID address = reinterpret_cast<LPVOID>(this->m_pos);
	SIZE_T written_bytes = 0;
	if (!WriteProcessMemory(this->m_handle, address, buf, size, &written_bytes))
	{
		DWORD last_error = GetLastError();
		std::stringstream ss;
		ss << "WriteProcessMemory failed, GLE: " << last_error;
		throw std::runtime_error(ss.str());
	}

	this->m_pos += written_bytes;
	return written_bytes;
}

bool process_stream::open(unsigned long pid)
{
	this->close();
	this->m_pid = pid;
	this->m_handle = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
	return this->is_open();
}
bool process_stream::open(const std::string& process_name)
{
	// close before open
	this->close();

	// Get the list of process identifiers.
	DWORD aProcesses[1024], cbNeeded;
	if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
	{
		return false;
	}

	// Calculate how many process identifiers were returned.
	DWORD cProcesses = cbNeeded / sizeof(DWORD);
	for (unsigned int i = 0; i < cProcesses; i++)
	{
		if (aProcesses[i] == 0)
			continue;

		// Get a handle to the process.
		HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
		if (hProcess == NULL)
			continue;

		CHAR szProcessName[MAX_PATH];
		if (GetModuleBaseNameA(hProcess, NULL, szProcessName, MAX_PATH) != 0
			&& process_name.compare(szProcessName) == 0)
		{
			// just break after close handle
			this->open(aProcesses[i]);
			i = cProcesses;
		}
		CloseHandle(hProcess);
	}

	return this->is_open();
}

unsigned long process_stream::pid() const
{
	return this->m_handle != NULL ? this->m_pid : 0;
}