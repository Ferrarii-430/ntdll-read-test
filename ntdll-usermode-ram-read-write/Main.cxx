#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <chrono>
#include <cstring>
#include <fstream>
#include <sstream>
#include <unordered_map>

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

struct DiffScanCandidate {
	std::uintptr_t address;
	double v0;
	double v1;
	double v2;
	double velocity;
};

struct DiffScanSnapshot {
	struct Block {
		std::uintptr_t base;
		std::vector<std::uint8_t> data;
	};

	std::vector<Block> blocks;
	std::size_t bytes = 0;
};

static std::vector<MEMORY_BASIC_INFORMATION> FilterWritableRegions(
	const std::vector<MEMORY_BASIC_INFORMATION>& regions
) {
	constexpr DWORD kWritable =
		PAGE_READWRITE | PAGE_WRITECOPY |
		PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

	std::vector<MEMORY_BASIC_INFORMATION> writable { };
	for (const auto& region : regions)
		if (region.State == MEM_COMMIT
			&& (region.Protect & kWritable)
			&& !(region.Protect & (PAGE_GUARD | PAGE_NOACCESS))
			&& region.RegionSize >= 0x1000)
			writable.push_back(region);

	return writable;
}

static DiffScanSnapshot TakeSnapshot(
	const Memory::PMemory memory,
	const std::vector<MEMORY_BASIC_INFORMATION>& regions
) {
	constexpr std::size_t kChunkSize = 0x10000;

	DiffScanSnapshot snapshot { };
	for (const auto& region : regions) {
		const auto regionBase = reinterpret_cast<std::uintptr_t>(region.BaseAddress);

		for (std::size_t offset = 0; offset < region.RegionSize; offset += kChunkSize) {
			const auto size = std::min(kChunkSize, region.RegionSize - offset);

			DiffScanSnapshot::Block block { regionBase + offset, std::vector<std::uint8_t>(size) };
			if (!memory->ReadRaw(block.base, block.data.data(), size)) continue;

			snapshot.bytes += size;
			snapshot.blocks.push_back(std::move(block));
		}
	}

	return snapshot;
}

static bool DiffScanSeries(
	const double a, const double b, const double c,
	const double minDelta, const double maxDelta, double& delta
) {
	if (!std::isfinite(a) || !std::isfinite(b) || !std::isfinite(c)) return false;

	const double delta1 = b - a;
	const double delta2 = c - b;
	if (delta1 == 0.0 || delta2 == 0.0 || delta1 * delta2 <= 0.0) return false;
	if (std::abs(delta1 - delta2) > 0.30 * std::max(std::abs(delta1), std::abs(delta2))) return false;

	delta = (delta1 + delta2) * 0.5;
	return std::abs(delta) >= minDelta && std::abs(delta) <= maxDelta;
}

static void DiffScanReport(
	const char* const type,
	std::vector<DiffScanCandidate> candidates,
	const std::uintptr_t moduleBase, const std::uintptr_t moduleSize,
	std::ostream& stream
) {
	std::sort(candidates.begin(), candidates.end(),
		[](const DiffScanCandidate& left, const DiffScanCandidate& right) {
			return left.velocity < right.velocity;
		});

	struct Group {
		double velocity;
		std::size_t count;
		std::size_t first;
	};

	std::vector<Group> groups { };
	for (std::size_t index = 0; index < candidates.size(); ++index) {
		const double tolerance = 0.05 * std::abs(candidates[index].velocity) + 1e-9;

		if (!groups.empty() && std::abs(candidates[index].velocity - groups.back().velocity) <= tolerance) {
			++groups.back().count;
			continue;
		}

		groups.push_back({ candidates[index].velocity, 1, index });
	}

	std::sort(groups.begin(), groups.end(),
		[](const Group& left, const Group& right) { return left.count > right.count; });

	stream << "\n[" << type << "] candidates = " << candidates.size()
		<< ", groups = " << groups.size() << std::endl;

	std::size_t shown = 0;
	for (const auto& group : groups) {
		if (++shown > 12) {
			stream << "  ... more groups omitted" << std::endl;
			break;
		}

		stream << "  v = " << std::setprecision(6) << group.velocity << " /s"
			<< ", count = " << group.count << std::endl;

		const auto limit = std::min<std::size_t>(group.count, 8);
		for (std::size_t index = 0; index < limit; ++index) {
			const auto& candidate = candidates[group.first + index];

			stream << "    0x" << std::hex << candidate.address << std::dec;
			if (candidate.address >= moduleBase && candidate.address < moduleBase + moduleSize)
				stream << " (onmyoji.exe+0x" << std::hex
					<< (candidate.address - moduleBase) << std::dec << ")";

			stream << "  " << std::setprecision(9)
				<< candidate.v0 << " -> " << candidate.v1 << " -> " << candidate.v2 << std::endl;
		}
	}
}

static int RunDiffScan(void) {
	Memory::PMemory memory { };

	try {
		memory = new Memory::Memory();
		memory->Attach(L"onmyoji.exe");

		const auto moduleBase = memory->GetModule(L"onmyoji.exe");
		const auto ntHeader = moduleBase + memory->Read<std::uint32_t>(moduleBase + 0x3C);
		const auto moduleSize = memory->Read<std::uint32_t>(ntHeader + 0x18 + 0x38);

		const auto regions = FilterWritableRegions(memory->GetRegions());

		std::size_t total = 0;
		for (const auto& region : regions) total += region.RegionSize;

		std::cout << "onmyoji.exe base = 0x" << std::hex << moduleBase << std::dec
			<< "\nwritable regions = " << regions.size()
			<< ", total = " << (total / 1024 / 1024) << " MB" << std::endl;

		std::cout << "snapshot A ..." << std::endl;
		const auto timeA = std::chrono::steady_clock::now();
		auto snapshotA = TakeSnapshot(memory, regions);

		Sleep(600);

		std::cout << "snapshot B ..." << std::endl;
		const auto timeB = std::chrono::steady_clock::now();
		auto snapshotB = TakeSnapshot(memory, regions);

		std::unordered_map<std::uintptr_t, std::size_t> snapshotBIndex { };
		for (std::size_t index = 0; index < snapshotB.blocks.size(); ++index)
			snapshotBIndex[snapshotB.blocks[index].base] = index;

		DiffScanSnapshot keptA { }, keptB { };
		for (auto& block : snapshotA.blocks) {
			const auto found = snapshotBIndex.find(block.base);
			if (found == snapshotBIndex.end()) continue;

			auto& other = snapshotB.blocks[found->second];
			if (other.data.size() != block.data.size()) continue;
			if (std::memcmp(block.data.data(), other.data.data(), block.data.size()) != 0) {
				keptA.bytes += block.data.size();
				keptA.blocks.push_back(std::move(block));

				keptB.bytes += other.data.size();
				keptB.blocks.push_back(std::move(other));
			}
		}

		snapshotA.blocks.clear();
		snapshotA.blocks.shrink_to_fit();
		snapshotB.blocks.clear();
		snapshotB.blocks.shrink_to_fit();

		std::cout << "changed blocks = " << keptA.blocks.size()
			<< " (" << (keptA.bytes / 1024 / 1024) << " MB)" << std::endl;

		Sleep(600);

		std::cout << "snapshot C ..." << std::endl;
		const auto timeC = std::chrono::steady_clock::now();

		DiffScanSnapshot snapshotC { };
		for (const auto& block : keptB.blocks) {
			DiffScanSnapshot::Block fresh { block.base, std::vector<std::uint8_t>(block.data.size()) };
			if (memory->ReadRaw(fresh.base, fresh.data.data(), fresh.data.size()))
				snapshotC.bytes += fresh.data.size();
			else fresh.data.clear();

			snapshotC.blocks.push_back(std::move(fresh));
		}

		const double dt1 = std::chrono::duration<double>(timeB - timeA).count();
		const double dt2 = std::chrono::duration<double>(timeC - timeB).count();

		std::cout << "snapshot C blocks = " << snapshotC.blocks.size()
			<< ", dt1 = " << dt1 << "s, dt2 = " << dt2 << "s" << std::endl;

		std::vector<DiffScanCandidate> floatCandidates { };
		std::vector<DiffScanCandidate> doubleCandidates { };
		std::vector<DiffScanCandidate> intCandidates { };

		for (std::size_t blockIndex = 0; blockIndex < keptA.blocks.size(); ++blockIndex) {
			const auto& blockA = keptA.blocks[blockIndex];
			const auto& blockB = keptB.blocks[blockIndex];
			const auto& blockC = snapshotC.blocks[blockIndex];

			if (blockB.data.size() != blockA.data.size()) continue;
			if (blockC.data.size() != blockA.data.size()) continue;

			for (std::size_t offset = 0; offset + 4 <= blockA.data.size(); offset += 4) {
				float fa { }, fb { }, fc { };
				std::memcpy(&fa, blockA.data.data() + offset, sizeof(fa));
				std::memcpy(&fb, blockB.data.data() + offset, sizeof(fb));
				std::memcpy(&fc, blockC.data.data() + offset, sizeof(fc));

				double delta = 0.0;
				if (DiffScanSeries(fa, fb, fc, 0.01, 1000000.0, delta))
					floatCandidates.push_back({ blockA.base + offset,
						fa, fb, fc, delta / ((dt1 + dt2) * 0.5) });

				std::int32_t ia { }, ib { }, ic { };
				std::memcpy(&ia, blockA.data.data() + offset, sizeof(ia));
				std::memcpy(&ib, blockB.data.data() + offset, sizeof(ib));
				std::memcpy(&ic, blockC.data.data() + offset, sizeof(ic));

				if (DiffScanSeries(static_cast<double>(ia), static_cast<double>(ib),
					static_cast<double>(ic), 1.0, 1000000.0, delta))
					intCandidates.push_back({ blockA.base + offset,
						static_cast<double>(ia), static_cast<double>(ib),
						static_cast<double>(ic), delta / ((dt1 + dt2) * 0.5) });
			}

			for (std::size_t offset = 0; offset + 8 <= blockA.data.size(); offset += 8) {
				double da { }, db { }, dc { };
				std::memcpy(&da, blockA.data.data() + offset, sizeof(da));
				std::memcpy(&db, blockB.data.data() + offset, sizeof(db));
				std::memcpy(&dc, blockC.data.data() + offset, sizeof(dc));

				double delta = 0.0;
				if (DiffScanSeries(da, db, dc, 0.01, 1000000.0, delta))
					doubleCandidates.push_back({ blockA.base + offset,
						da, db, dc, delta / ((dt1 + dt2) * 0.5) });
			}
		}

		std::ostringstream report { };
		DiffScanReport("float", floatCandidates, moduleBase, moduleSize, report);
		DiffScanReport("double", doubleCandidates, moduleBase, moduleSize, report);
		DiffScanReport("int32", intCandidates, moduleBase, moduleSize, report);

		std::cout << report.str();

		std::ofstream file("diffscan.txt", std::ios::trunc);
		if (file) {
			file << report.str();
			std::cout << "\n[saved] diffscan.txt" << std::endl;
		}
	}
	catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;

		delete memory;

		return 1;
	}

	delete memory;

	return 0;
}

static int RunRecon(void) {
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

int main(const int argc, char* argv[]) {
	if (argc > 1 && std::string(argv[1]) == "--diffscan") return RunDiffScan();

	return RunRecon();
}
