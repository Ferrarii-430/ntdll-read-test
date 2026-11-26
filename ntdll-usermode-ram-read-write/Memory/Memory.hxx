/*
    File Memory.hxx
    By WzrterFX
*/

#ifndef MEMORY_HXX
#define MEMORY_HXX

#pragma once

#define NOMINMAX
#include <cstdint>
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace Memory {
    using pid_t = std::uint32_t;

    namespace __NtdllApi {
        typedef struct _CLIENT_ID {
            HANDLE UniqueProcess;
            HANDLE UniqueThread;
        } CLIENT_ID, * PCLIENT_ID;

        typedef struct _OBJECT_ATTRIBUTES {
            ULONG Length;
            HANDLE RootDirectory;
            PUNICODE_STRING ObjectName;
            ULONG Attributes;
            PVOID SecurityDescriptor;
            PVOID SecurityQualityOfService;
        } OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

        extern NTSTATUS(NTAPI* NtOpenProcess)(
            PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID
        );

        extern NTSTATUS(NTAPI* NtReadVirtualMemory)(
            HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T
        );
        extern NTSTATUS(NTAPI* NtWriteVirtualMemory)(
            HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T
        );

        extern NTSTATUS(NTAPI* NtQueryVirtualMemory)(
            HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T
        );
    }

    class Memory final {
        Memory(const Memory&) = delete;
        Memory& operator=(const Memory&) = delete;

    private:
        pid_t _pid;

        HANDLE _handle;

    public:
        Memory();
        ~Memory();

        void Attach(const std::wstring& name);

        // 进程句柄 (NtSuspendProcess/NtResumeProcess 等扩展 API 用)
        [[nodiscard]] HANDLE Handle() const { return _handle; }

        [[nodiscard]] bool ReadRaw(
            const std::uintptr_t address, void* buffer, const std::size_t size
        ) const;

        // 容错读取: 返回实际读取的字节数 (>=0); 跨保留页的部分拷贝
        // (STATUS_PARTIAL_COPY) 也算成功, 缓冲区前 got 字节有效
        [[nodiscard]] std::size_t ReadPartial(
            const std::uintptr_t address, void* buffer, const std::size_t size
        ) const;

        // 读取失败时返回 false，不修改 out，用于扫描等允许失败的场景
        template<typename T>
        [[nodiscard]] bool TryRead(const std::uintptr_t address, T& out) const {
            return ReadRaw(address, &out, sizeof(T));
        }

        // 读取失败时抛异常，用于必须成功的关键读取
        template<typename T>
        [[nodiscard]] T Read(const std::uintptr_t address) const {
            T readed { };
            if (!ReadRaw(address, &readed, sizeof(T))) throw std::runtime_error(
                "::Memory read failed at address."
            );

            return readed;
        }

        // 读取失败时返回 fallback，用于容错读取
        template<typename T>
        [[nodiscard]] T ReadOr(const std::uintptr_t address, const T& fallback) const {
            T readed { };
            return ReadRaw(address, &readed, sizeof(T)) ? readed : fallback;
        }

        template<typename T>
        void Write(const std::uintptr_t address, const T& value) const {
            if (!_handle) throw std::runtime_error(
                "::Memory write no access, ::_handle missing."
            );

            __NtdllApi::NtWriteVirtualMemory(
                _handle, reinterpret_cast<PVOID>(address), const_cast<T*>(&value), sizeof(T), nullptr
            );
        }

        [[nodiscard]] std::uintptr_t GetModule(const std::wstring& name) const;

        [[nodiscard]] std::vector<std::uint8_t> ReadBytes(
            const std::uintptr_t address, const std::size_t size
        ) const;

        [[nodiscard]] std::wstring ReadWideString(
            const std::uintptr_t address, const std::size_t maxLength = 64
        ) const;

        [[nodiscard]] std::vector<MEMORY_BASIC_INFORMATION> GetRegions() const;

        // 逐级解引用指针链，最后一个偏移只做相加，返回最终数据地址；任一级为空返回 0
        [[nodiscard]] std::uintptr_t ReadChain(
            std::uintptr_t base, const std::vector<std::uintptr_t>& offsets
        ) const;

        // 在可读已提交区域内按 sizeof(T) 对齐扫描指定值
        template<typename T>
        [[nodiscard]] std::vector<std::uintptr_t> ScanValue(
            const T& value, const std::size_t limit = 512
        ) const {
            std::vector<std::uintptr_t> found { };
            std::vector<std::uint8_t> page { };

            for (const auto& region : GetRegions()) {
                const auto regionBase = reinterpret_cast<std::uintptr_t>(region.BaseAddress);

                page.resize(region.RegionSize);
                if (!ReadRaw(regionBase, page.data(), page.size())) continue;

                for (std::size_t offset = 0; offset + sizeof(T) <= page.size(); offset += sizeof(T)) {
                    if (std::memcmp(page.data() + offset, &value, sizeof(T)) != 0) continue;

                    found.push_back(regionBase + offset);
                    if (found.size() >= limit) return found;
                }
            }

            return found;
        }
    };

    using PMemory = Memory*;
}

#endif /* !MEMORY_HXX */
