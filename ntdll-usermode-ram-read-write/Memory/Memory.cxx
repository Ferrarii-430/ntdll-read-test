/*
    File Memory.cxx
    By WzrterFX
*/

#include "Memory.hxx"

namespace Memory {
    NTSTATUS(NTAPI* __NtdllApi::NtOpenProcess)(
        PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID
    ) = nullptr;

    NTSTATUS(NTAPI* __NtdllApi::NtReadVirtualMemory)(
        HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T
    ) = nullptr;
    NTSTATUS(NTAPI* __NtdllApi::NtWriteVirtualMemory)(
        HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T
    ) = nullptr;

    NTSTATUS(NTAPI* __NtdllApi::NtQueryVirtualMemory)(
        HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T
    ) = nullptr;

	Memory::Memory() 
        : _pid(0), _handle(nullptr) {

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        if (!ntdll) throw std::runtime_error(
            "::Memory failed to load 'ntdll.dll'."
        );

        __NtdllApi::NtOpenProcess = reinterpret_cast<decltype(__NtdllApi::NtOpenProcess)>(
            GetProcAddress(ntdll, "NtOpenProcess")
        ); if (!__NtdllApi::NtOpenProcess) throw std::runtime_error(
            "::Memory failed to load 'NtOpenProcess'."
        );

        __NtdllApi::NtReadVirtualMemory = reinterpret_cast<decltype(__NtdllApi::NtReadVirtualMemory)>(
            GetProcAddress(ntdll, "NtReadVirtualMemory")
        ); if (!__NtdllApi::NtReadVirtualMemory) throw std::runtime_error(
            "::Memory failed to load 'NtReadVirtualMemory'."
        );
        __NtdllApi::NtWriteVirtualMemory = reinterpret_cast<decltype(__NtdllApi::NtWriteVirtualMemory)>(
            GetProcAddress(ntdll, "NtWriteVirtualMemory")
        ); if (!__NtdllApi::NtWriteVirtualMemory) throw std::runtime_error(
            "::Memory failed to load 'NtWriteVirtualMemory'."
        );

        __NtdllApi::NtQueryVirtualMemory = reinterpret_cast<decltype(__NtdllApi::NtQueryVirtualMemory)>(
            GetProcAddress(ntdll, "NtQueryVirtualMemory")
        ); if (!__NtdllApi::NtQueryVirtualMemory) throw std::runtime_error(
            "::Memory failed to load 'NtQueryVirtualMemory'."
        );
    };

	Memory::~Memory() {
        if (_handle) {
            CloseHandle(_handle);

            _pid = 0;
            _handle = nullptr;
        }
    }

    std::uintptr_t Memory::GetModule(const std::wstring& name) const {
        if (!_handle) throw std::runtime_error(
            "::Memory module no access, ::_handle missing."
        );

        MODULEENTRY32W moduleEntry32w { };
        moduleEntry32w.dwSize = sizeof(moduleEntry32w);

        HANDLE toolhelp32Snapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, _pid
        ); if (!toolhelp32Snapshot) throw std::runtime_error(
            "::Memory failed to 'CreateToolhelp32Snapshot', make sure what you have access."
        );

        if (!Module32FirstW(toolhelp32Snapshot, &moduleEntry32w)) {
            CloseHandle(toolhelp32Snapshot);

            throw std::runtime_error(
                "::Memory failed, first module missing."
            );
        }

        do {
            if (_wcsicmp(moduleEntry32w.szModule, name.c_str()) == 0) {
                CloseHandle(toolhelp32Snapshot);

                return reinterpret_cast<std::uintptr_t>(moduleEntry32w.modBaseAddr);
            }
        } while (Module32NextW(toolhelp32Snapshot, &moduleEntry32w));

        CloseHandle(toolhelp32Snapshot);

        throw std::runtime_error(
            "::Memory module '" + std::string(name.begin(), name.end()) + "'."
        );
    }

    void Memory::Attach(const std::wstring& name) {
        if (_handle) Memory::~Memory();

        PROCESSENTRY32W processEntry32w { };
        processEntry32w.dwSize = sizeof(processEntry32w);

        HANDLE toolhelp32Snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (!toolhelp32Snapshot) throw std::runtime_error(
            "::Memory failed to 'CreateToolhelp32Snapshot', make sure what you have access."
        );

        if (Process32FirstW(toolhelp32Snapshot, &processEntry32w)) {
            do {
                if (name == processEntry32w.szExeFile) {
                    _pid = processEntry32w.th32ProcessID;

                    break;
                }
            } while (Process32NextW(toolhelp32Snapshot, &processEntry32w));
        }

        CloseHandle(toolhelp32Snapshot);

        if (!_pid) throw std::runtime_error(
            "::Memory failed to + '" + std::string(name.begin(), name.end()) + "' + ::_pid."
        );

        __NtdllApi::OBJECT_ATTRIBUTES objectAttributes { };
        InitializeObjectAttributes(
            &objectAttributes, nullptr, 0, nullptr, nullptr
        );

        __NtdllApi::CLIENT_ID clientId{ };
        clientId.UniqueProcess = reinterpret_cast<HANDLE>(static_cast<DWORD_PTR>(_pid));
        clientId.UniqueThread = nullptr;

        //PROCESS_VM_WRITE 移除写权限
        __NtdllApi::NtOpenProcess(
            &_handle, PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, &objectAttributes, &clientId
        ); if (!_handle) throw std::runtime_error(
            "::Memory failed to ::_handle with '" + std::string(name.begin(), name.end()) + "'."
        );
    }

    bool Memory::ReadRaw(
        const std::uintptr_t address, void* buffer, const std::size_t size
    ) const {
        if (!_handle) throw std::runtime_error(
            "::Memory read no access, ::_handle missing."
        );

        if (!address || !buffer || !size) return false;

        SIZE_T readed = 0;
        const NTSTATUS status = __NtdllApi::NtReadVirtualMemory(
            _handle, reinterpret_cast<PVOID>(address), buffer, size, &readed
        );

        return status >= 0 && readed == size;
    }

    std::size_t Memory::ReadPartial(
        const std::uintptr_t address, void* buffer, const std::size_t size
    ) const {
        if (!_handle) throw std::runtime_error(
            "::Memory read no access, ::_handle missing."
        );

        if (!address || !buffer || !size) return 0;

        SIZE_T readed = 0;
        // 部分拷贝返回 STATUS_PARTIAL_COPY (负值), 但 readed 字节有效
        __NtdllApi::NtReadVirtualMemory(
            _handle, reinterpret_cast<PVOID>(address), buffer, size, &readed
        );

        return static_cast<std::size_t>(readed);
    }

    std::vector<std::uint8_t> Memory::ReadBytes(
        const std::uintptr_t address, const std::size_t size
    ) const {
        std::vector<std::uint8_t> buffer(size);

        if (!ReadRaw(address, buffer.data(), size)) buffer.clear();
        return buffer;
    }

    std::wstring Memory::ReadWideString(
        const std::uintptr_t address, const std::size_t maxLength
    ) const {
        const auto bytes = ReadBytes(address, maxLength * sizeof(wchar_t));
        if (bytes.empty()) return { };

        const auto* characters = reinterpret_cast<const wchar_t*>(bytes.data());

        std::wstring result { };
        for (std::size_t index = 0; index < maxLength && characters[index]; ++index)
            result.push_back(characters[index]);

        return result;
    }

    std::vector<MEMORY_BASIC_INFORMATION> Memory::GetRegions() const {
        if (!_handle) throw std::runtime_error(
            "::Memory query no access, ::_handle missing."
        );

        constexpr DWORD kReadable =
            PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        constexpr DWORD kBlocked = PAGE_GUARD | PAGE_NOACCESS;

        std::vector<MEMORY_BASIC_INFORMATION> regions { };

        std::uintptr_t address = 0;
        MEMORY_BASIC_INFORMATION information { };

        while (__NtdllApi::NtQueryVirtualMemory(
            _handle, reinterpret_cast<PVOID>(address), 0,
            &information, sizeof(information), nullptr
        ) >= 0) {
            if (!information.RegionSize) break;

            if (information.State == MEM_COMMIT
                && (information.Protect & kReadable)
                && !(information.Protect & kBlocked)) regions.push_back(information);

            const std::uintptr_t next = address + information.RegionSize;
            if (next <= address) break;

            address = next;
        }

        return regions;
    }

    std::uintptr_t Memory::ReadChain(
        std::uintptr_t base, const std::vector<std::uintptr_t>& offsets
    ) const {
        if (!base || offsets.empty()) return 0;

        for (std::size_t index = 0; index < offsets.size(); ++index) {
            base += offsets[index];
            if (index + 1 == offsets.size()) break;

            if (!ReadRaw(base, &base, sizeof(base)) || !base) return 0;
        }

        return base;
    }
}