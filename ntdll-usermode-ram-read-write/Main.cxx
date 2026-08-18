#include <iostream>
#include <iomanip>
#include <cstdlib>

#include "Memory/Memory.hxx"

static void HexDump(
	const Memory::PMemory memory, const std::uintptr_t address, const std::size_t size
) {
	const auto bytes = memory->ReadBytes(address, size);
	if (bytes.empty()) {
		std::cout << "  <unreadable>" << std::endl;

		return;
	}

	for (std::size_t offset = 0; offset < bytes.size(); offset += 16) {
		std::cout << "  +0x" << std::hex << std::setw(4) << std::setfill('0') << offset << "  ";

		for (std::size_t index = 0; index < 16; ++index) {
			if (offset + index < bytes.size()) std::cout << std::setw(2) << std::setfill('0')
				<< static_cast<std::uint32_t>(bytes[offset + index]) << ' ';
			else std::cout << "   ";
		}

		std::cout << "| ";
		for (std::size_t index = 0; index < 16 && offset + index < bytes.size(); ++index) {
			const auto character = bytes[offset + index];

			std::cout << (character >= 0x20 && character < 0x7F
				? static_cast<char>(character) : '.');
		}

		std::cout << std::endl;
	}

	std::cout << std::dec << std::setfill(' ');
}

int main(void) {
	Memory::PMemory memory { };

	try {
		memory = new Memory::Memory();

		memory->Attach(L"onmyoji.exe");

		const auto base = memory->GetModule(L"onmyoji.exe");
		std::cout << "onmyoji.exe base = 0x" << std::hex << base << std::dec << std::endl;

		// 1. DOS 头：e_magic 应为 0x5A4D ("MZ")，验证句柄与基址均有效
		const auto dosMagic = memory->Read<std::uint16_t>(base);
		if (dosMagic != 0x5A4D) throw std::runtime_error(
			"::Main invalid DOS magic, base may be wrong."
		);

		// 2. e_lfanew 位于 +0x3C，指向 NT 头；验证多级间接寻址可用
		const auto ntHeader = base + memory->Read<std::uint32_t>(base + 0x3C);
		if (memory->Read<std::uint32_t>(ntHeader) != 0x00004550) throw std::runtime_error(
			"::Main invalid PE signature."
		);

		// 3. FileHeader (+0x04) 与 OptionalHeader (+0x18) 的关键字段
		const auto machine = memory->Read<std::uint16_t>(ntHeader + 0x04);
		const auto sectionCount = memory->Read<std::uint16_t>(ntHeader + 0x06);
		const auto optionalSize = memory->Read<std::uint16_t>(ntHeader + 0x14);

		const auto entryPoint = memory->Read<std::uint32_t>(ntHeader + 0x18 + 0x10);
		const auto imageBase = memory->Read<std::uint64_t>(ntHeader + 0x18 + 0x18);
		const auto imageSize = memory->Read<std::uint32_t>(ntHeader + 0x18 + 0x38);

		std::cout << std::hex
			<< "machine      = 0x" << machine << (machine == 0x8664 ? " (x64)" : " (?)") << '\n'
			<< "entry point  = 0x" << (base + entryPoint) << '\n'
			<< "image base   = 0x" << imageBase << '\n'
			<< "image size   = 0x" << imageSize << '\n'
			<< "aslr delta   = 0x" << (base - imageBase) << '\n'
			<< "sections     = " << std::dec << sectionCount << std::endl;

		// 4. 节区表紧跟 OptionalHeader，每项 0x28 字节；据此划定后续扫描范围
		const auto sectionTable = ntHeader + 0x18 + optionalSize;

		std::cout << "\n[sections]" << std::endl;
		for (std::uint16_t index = 0; index < sectionCount; ++index) {
			const auto entry = sectionTable + index * 0x28;

			char name[9] { };
			if (!memory->ReadRaw(entry, name, 8)) continue;

			const auto virtualSize = memory->Read<std::uint32_t>(entry + 0x08);
			const auto virtualAddress = memory->Read<std::uint32_t>(entry + 0x0C);

			std::cout << "  " << std::setw(8) << std::setfill(' ') << std::left << name
				<< std::right << std::hex
				<< "  0x" << (base + virtualAddress)
				<< " - 0x" << (base + virtualAddress + virtualSize)
				<< "  size=0x" << virtualSize << std::dec << std::endl;
		}

		// 5. hex dump：肉眼识别 float / 指针 / 字符串
		std::cout << "\n[dump] base .. base+0x40" << std::endl;
		HexDump(memory, base, 0x40);

		// 6. 可读已提交区域概览，作为扫描的总体边界
		const auto regions = memory->GetRegions();

		std::size_t total = 0;
		for (const auto& region : regions) total += region.RegionSize;

		std::cout << "\n[regions] count = " << regions.size()
			<< ", total = " << (total / 1024 / 1024) << " MB" << std::endl;

		// 7. 指针链模板：偏移需自行用 CE / x64dbg 确认后替换
		// const auto address = memory->ReadChain(base, { 0x1A2B3C8, 0x28, 0x1C });
		// if (address) std::cout << "value = " << memory->Read<std::int32_t>(address) << std::endl;
	}
	catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;
	}

	delete memory;

	return 0;
}
