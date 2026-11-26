#include <iostream>
#include <iomanip>
#include <cstdlib>
#include <cmath>
#include <chrono>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <unordered_map>

#include "Memory/Memory.hxx"
#include "GhostWalk/GhostWalk.hxx"

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

static bool DiffScanFloatBitsPlausible(const std::uint32_t bits) {
	float value { };
	std::memcpy(&value, &bits, sizeof(value));

	return std::isfinite(value)
		&& std::abs(value) >= 1e-3f && std::abs(value) <= 1e7f;
}

// 三快照: A/B 全量, 取值有变化的块, 再补读 C; 供 diffscan 与 autowatch 复用
struct DiffScanTriple {
	DiffScanSnapshot a;
	DiffScanSnapshot b;
	DiffScanSnapshot c;
	double dt1 = 0.0;
	double dt2 = 0.0;
};

static DiffScanTriple TakeTripleSnapshots(
	const Memory::PMemory memory,
	const std::vector<MEMORY_BASIC_INFORMATION>& regions,
	const DWORD gapMs
) {
	DiffScanTriple triple { };

	std::cout << "snapshot A ..." << std::endl;
	const auto timeA = std::chrono::steady_clock::now();
	auto snapshotA = TakeSnapshot(memory, regions);

	Sleep(gapMs);

	std::cout << "snapshot B ..." << std::endl;
	const auto timeB = std::chrono::steady_clock::now();
	auto snapshotB = TakeSnapshot(memory, regions);

	std::unordered_map<std::uintptr_t, std::size_t> snapshotBIndex { };
	for (std::size_t index = 0; index < snapshotB.blocks.size(); ++index)
		snapshotBIndex[snapshotB.blocks[index].base] = index;

	for (auto& block : snapshotA.blocks) {
		const auto found = snapshotBIndex.find(block.base);
		if (found == snapshotBIndex.end()) continue;

		auto& other = snapshotB.blocks[found->second];
		if (other.data.size() != block.data.size()) continue;
		if (std::memcmp(block.data.data(), other.data.data(), block.data.size()) != 0) {
			triple.a.bytes += block.data.size();
			triple.a.blocks.push_back(std::move(block));

			triple.b.bytes += other.data.size();
			triple.b.blocks.push_back(std::move(other));
		}
	}

	Sleep(gapMs);

	std::cout << "snapshot C ..." << std::endl;
	const auto timeC = std::chrono::steady_clock::now();

	for (const auto& block : triple.b.blocks) {
		DiffScanSnapshot::Block fresh { block.base, std::vector<std::uint8_t>(block.data.size()) };
		if (memory->ReadRaw(fresh.base, fresh.data.data(), fresh.data.size()))
			triple.c.bytes += fresh.data.size();
		else fresh.data.clear();

		triple.c.blocks.push_back(std::move(fresh));
	}

	triple.dt1 = std::chrono::duration<double>(timeB - timeA).count();
	triple.dt2 = std::chrono::duration<double>(timeC - timeB).count();

	return triple;
}

// 提取三快照中匀速变化的 float 候选
static void CollectFloatCandidates(
	const DiffScanTriple& triple,
	std::vector<DiffScanCandidate>& candidates
) {
	const double dt = (triple.dt1 + triple.dt2) * 0.5;
	if (dt <= 0.0) return;

	for (std::size_t blockIndex = 0; blockIndex < triple.a.blocks.size(); ++blockIndex) {
		const auto& blockA = triple.a.blocks[blockIndex];
		const auto& blockB = triple.b.blocks[blockIndex];
		const auto& blockC = triple.c.blocks[blockIndex];

		if (blockB.data.size() != blockA.data.size()) continue;
		if (blockC.data.size() != blockA.data.size()) continue;

		for (std::size_t offset = 0; offset + 4 <= blockA.data.size(); offset += 4) {
			float fa { }, fb { }, fc { };
			std::memcpy(&fa, blockA.data.data() + offset, sizeof(fa));
			std::memcpy(&fb, blockB.data.data() + offset, sizeof(fb));
			std::memcpy(&fc, blockC.data.data() + offset, sizeof(fc));

			double delta = 0.0;
			if (DiffScanSeries(fa, fb, fc, 0.01, 1000000.0, delta))
				candidates.push_back({ blockA.base + offset, fa, fb, fc, delta / dt });
		}
	}
}

// 同步值组: 同一份数据在内存中存在多份拷贝(逻辑/渲染等), 同时刻值完全相同
struct AutoWatchGroup {
	std::uintptr_t address; // 组内代表地址
	std::size_t copies;     // 组内同步地址数
	double v1;              // B 时刻值(聚类键)
	double velocity;        // 平均速度
};

// 按 B 时刻值聚类: 值完全相同的匀速候选归为一组, 即同一份数据的多份拷贝
static std::vector<AutoWatchGroup> ClusterByValue(std::vector<DiffScanCandidate> candidates) {
	std::sort(candidates.begin(), candidates.end(),
		[](const DiffScanCandidate& left, const DiffScanCandidate& right) {
			return left.v1 < right.v1;
		});

	std::vector<AutoWatchGroup> groups { };

	std::size_t begin = 0;
	while (begin < candidates.size()) {
		std::size_t end = begin + 1;
		while (end < candidates.size()
			&& std::abs(candidates[end].v1 - candidates[end - 1].v1) <= 0.25)
			++end;

		if (end - begin >= 2) {
			double velocity = 0.0;
			for (std::size_t index = begin; index < end; ++index)
				velocity += candidates[index].velocity;
			velocity /= static_cast<double>(end - begin);

			// 速度与数值范围过滤: 排除 UI 动画/音频等噪声, 保留屏幕坐标量级
			if (std::abs(velocity) >= 1.0 && std::abs(velocity) <= 500.0
				&& std::abs(candidates[begin].v1) <= 10000.0)
				groups.push_back({ candidates[begin].address, end - begin,
					candidates[begin].v1, velocity });
		}

		begin = end;
	}

	std::sort(groups.begin(), groups.end(),
		[](const AutoWatchGroup& left, const AutoWatchGroup& right) {
			return left.copies > right.copies;
		});

	return groups;
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

	std::size_t singles = 0;
	std::vector<const Group*> largeGroups { }, smallGroups { };
	for (const auto& group : groups) {
		if (group.count == 1) ++singles;
		else if (group.count <= 64) smallGroups.push_back(&group);
		else largeGroups.push_back(&group);
	}

	stream << "\n[" << type << "] candidates = " << candidates.size()
		<< ", groups = " << groups.size()
		<< ", singles = " << singles << std::endl;

	std::sort(largeGroups.begin(), largeGroups.end(),
		[](const Group* left, const Group* right) { return left->count > right->count; });
	std::sort(smallGroups.begin(), smallGroups.end(),
		[](const Group* left, const Group* right) { return left->count < right->count; });

	const auto printGroup = [&](const Group& group, const std::size_t memberLimit) {
		stream << "  v = " << std::setprecision(6) << group.velocity << " /s"
			<< ", count = " << group.count << std::endl;

		const auto limit = std::min<std::size_t>(group.count, memberLimit);
		for (std::size_t index = 0; index < limit; ++index) {
			const auto& candidate = candidates[group.first + index];

			stream << "    0x" << std::hex << candidate.address << std::dec;
			if (candidate.address >= moduleBase && candidate.address < moduleBase + moduleSize)
				stream << " (onmyoji.exe+0x" << std::hex
					<< (candidate.address - moduleBase) << std::dec << ")";

			stream << "  " << std::setprecision(9)
				<< candidate.v0 << " -> " << candidate.v1 << " -> " << candidate.v2 << std::endl;
		}
	};

	if (!smallGroups.empty()) {
		stream << "  -- small groups (2..64), suspects --" << std::endl;

		std::size_t shown = 0;
		for (const auto* group : smallGroups) {
			if (++shown > 100) {
				stream << "  ... more small groups omitted" << std::endl;
				break;
			}

			printGroup(*group, 32);
		}
	}

	if (!largeGroups.empty()) {
		stream << "  -- large groups (count > 64), context --" << std::endl;

		const auto limit = std::min<std::size_t>(largeGroups.size(), 8);
		for (std::size_t index = 0; index < limit; ++index) printGroup(*largeGroups[index], 4);
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

		const auto triple = TakeTripleSnapshots(memory, regions, 600);

		std::cout << "changed blocks = " << triple.a.blocks.size()
			<< " (" << (triple.a.bytes / 1024 / 1024) << " MB)" << std::endl;
		std::cout << "snapshot C blocks = " << triple.c.blocks.size()
			<< ", dt1 = " << triple.dt1 << "s, dt2 = " << triple.dt2 << "s" << std::endl;

		std::vector<DiffScanCandidate> floatCandidates { };
		CollectFloatCandidates(triple, floatCandidates);

		std::vector<DiffScanCandidate> doubleCandidates { };
		std::vector<DiffScanCandidate> intCandidates { };

		const double dt = (triple.dt1 + triple.dt2) * 0.5;

		for (std::size_t blockIndex = 0; blockIndex < triple.a.blocks.size(); ++blockIndex) {
			const auto& blockA = triple.a.blocks[blockIndex];
			const auto& blockB = triple.b.blocks[blockIndex];
			const auto& blockC = triple.c.blocks[blockIndex];

			if (blockB.data.size() != blockA.data.size()) continue;
			if (blockC.data.size() != blockA.data.size()) continue;

			for (std::size_t offset = 0; offset + 4 <= blockA.data.size(); offset += 4) {
				std::int32_t ia { }, ib { }, ic { };
				std::memcpy(&ia, blockA.data.data() + offset, sizeof(ia));
				std::memcpy(&ib, blockB.data.data() + offset, sizeof(ib));
				std::memcpy(&ic, blockC.data.data() + offset, sizeof(ic));

				double delta = 0.0;
				if (DiffScanSeries(static_cast<double>(ia), static_cast<double>(ib),
					static_cast<double>(ic), 1.0, 1000000.0, delta)
					&& !DiffScanFloatBitsPlausible(static_cast<std::uint32_t>(ia))
					&& !DiffScanFloatBitsPlausible(static_cast<std::uint32_t>(ib))
					&& !DiffScanFloatBitsPlausible(static_cast<std::uint32_t>(ic)))
					intCandidates.push_back({ blockA.base + offset,
						static_cast<double>(ia), static_cast<double>(ib),
						static_cast<double>(ic), delta / dt });
			}

			for (std::size_t offset = 0; offset + 8 <= blockA.data.size(); offset += 8) {
				double da { }, db { }, dc { };
				std::memcpy(&da, blockA.data.data() + offset, sizeof(da));
				std::memcpy(&db, blockB.data.data() + offset, sizeof(db));
				std::memcpy(&dc, blockC.data.data() + offset, sizeof(dc));

				double delta = 0.0;
				if (DiffScanSeries(da, db, dc, 0.01, 1000000.0, delta)) {
					const double velocity = delta / dt;

					bool packedFloats = false;
					if (std::abs(velocity) > 100.0) {
						const double series[3] = { da, db, dc };
						for (const double value : series) {
							std::uint64_t bits = 0;
							std::memcpy(&bits, &value, sizeof(bits));

							if (DiffScanFloatBitsPlausible(static_cast<std::uint32_t>(bits >> 32))
								|| DiffScanFloatBitsPlausible(static_cast<std::uint32_t>(bits & 0xFFFFFFFF))) {
								packedFloats = true;
								break;
							}
						}
					}

					if (!packedFloats) doubleCandidates.push_back({ blockA.base + offset,
						da, db, dc, velocity });
				}
			}
		}

		std::ofstream csv("diffscan.csv", std::ios::trunc);
		if (csv) {
			csv << "type,address,v0,v1,v2,velocity" << '\n';

			const auto writeType = [&](const char* const type,
				const std::vector<DiffScanCandidate>& list) {
				for (const auto& candidate : list)
					csv << type << ",0x" << std::hex << candidate.address << std::dec << ','
						<< std::setprecision(9) << candidate.v0 << ',' << candidate.v1
						<< ',' << candidate.v2 << ',' << std::setprecision(6)
						<< candidate.velocity << '\n';
			};

			writeType("float", floatCandidates);
			writeType("double", doubleCandidates);
			writeType("int32", intCandidates);
		}

		std::ostringstream report { };
		DiffScanReport("float", floatCandidates, moduleBase, moduleSize, report);
		DiffScanReport("double", doubleCandidates, moduleBase, moduleSize, report);
		DiffScanReport("int32", intCandidates, moduleBase, moduleSize, report);

		std::cout << report.str();

		std::ofstream file("diffscan.txt", std::ios::trunc);
		if (file) {
			file << report.str();
			std::cout << "\n[saved] diffscan.txt"
				<< (csv ? ", diffscan.csv" : "") << std::endl;
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

static int RunRefs(const std::uintptr_t target) {
	Memory::PMemory memory { };

	try {
		memory = new Memory::Memory();
		memory->Attach(L"onmyoji.exe");

		std::cout << "target = 0x" << std::hex << target << std::dec << std::endl;

		const auto references = memory->ScanValue<std::uint64_t>(target);
		std::cout << "references = " << references.size() << std::endl;

		for (const auto& reference : references) {
			std::cout << "\n[ref] 0x" << std::hex << reference << std::dec << std::endl;
			HexDump(memory, reference >= 0x18 ? reference - 0x18 : reference, 0x38);
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

// --dump: 按 4 字节字转储，同时给出 hex / float / int32 三种解释，用于逆向结构体布局
static int RunDump(const std::uintptr_t address, const std::size_t size) {
	Memory::PMemory memory { };

	try {
		memory = new Memory::Memory();
		memory->Attach(L"onmyoji.exe");

		const auto bytes = memory->ReadBytes(address, size);
		if (bytes.empty()) {
			std::cout << "<unreadable>" << std::endl;
		}
		else {
			std::cout << "dump 0x" << std::hex << address << " .. +0x" << size << std::dec
				<< " (" << bytes.size() << " bytes)" << std::endl;

			for (std::size_t offset = 0; offset + 4 <= bytes.size(); offset += 4) {
				std::uint32_t word = 0;
				std::memcpy(&word, bytes.data() + offset, sizeof(word));

				float asFloat = 0.0f;
				std::memcpy(&asFloat, &word, sizeof(asFloat));

				std::cout << "  +0x" << std::hex << std::setw(4) << std::setfill('0')
					<< offset << std::dec << std::setfill(' ')
					<< "  0x" << std::hex << std::setw(8) << word << std::dec
					<< "  f=" << std::setw(14) << asFloat
					<< "  i=" << std::setw(12) << static_cast<std::int32_t>(word)
					<< std::endl;
			}
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

// 地址规格: "addr" 单地址，或 "addr:stride:count" 展开为 addr + k*stride (k = 0..count-1)
static std::vector<std::uintptr_t> ParseWatchAddresses(const std::vector<std::string>& specs) {
	std::vector<std::uintptr_t> addresses { };

	for (const auto& spec : specs) {
		const auto first = spec.find(':');
		if (first == std::string::npos) {
			addresses.push_back(
				static_cast<std::uintptr_t>(std::strtoull(spec.c_str(), nullptr, 16))
			);

			continue;
		}

		const auto second = spec.find(':', first + 1);
		if (second == std::string::npos) continue;

		const auto base = std::strtoull(spec.substr(0, first).c_str(), nullptr, 16);
		const auto stride = std::strtoull(
			spec.substr(first + 1, second - first - 1).c_str(), nullptr, 16
		);
		const auto count = std::strtoull(spec.substr(second + 1).c_str(), nullptr, 10);

		for (std::uint64_t index = 0; index < count; ++index)
			addresses.push_back(static_cast<std::uintptr_t>(base + index * stride));
	}

	return addresses;
}

// 监控循环: 轮询一组地址, 表格原地刷新, 显示当前值与相对上次轮询的变化量
static int WatchLoop(
	const Memory::PMemory memory,
	const std::vector<std::uintptr_t>& addresses,
	const std::vector<std::string>& labels,
	const int intervalMs
) {
	const std::size_t count = addresses.size();
	std::vector<float> current(count, 0.0f), previous(count, 0.0f);
	std::vector<bool> ok(count, false), okPrevious(count, false);

	// 启用 VT 转义序列，表格原地刷新；不支持时退化为滚动日志
	HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD mode = 0;
	const bool vt = console != INVALID_HANDLE_VALUE
		&& GetConsoleMode(console, &mode)
		&& SetConsoleMode(console, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

	std::cout << "watching " << count << " addresses every "
		<< intervalMs << " ms (Ctrl+C 退出)" << std::endl;

	bool drawn = false;
	while (true) {
		for (std::size_t index = 0; index < count; ++index) {
			float value = 0.0f;

			ok[index] = memory->TryRead(addresses[index], value);
			if (ok[index]) current[index] = value;
		}

		if (vt && drawn) std::cout << "\x1b[" << count << "A";

		for (std::size_t index = 0; index < count; ++index) {
			std::cout << "  " << std::setw(8) << std::left << labels[index] << std::right
				<< " 0x" << std::hex << addresses[index] << std::dec;

			if (!ok[index]) {
				std::cout << "  <unreadable>     ";
			}
			else if (!okPrevious[index]) {
				std::cout << "  " << std::setw(14) << current[index] << "  (new)      ";
			}
			else {
				const auto delta = current[index] - previous[index];

				std::cout << "  " << std::setw(14) << current[index]
					<< "  d=" << std::setw(11) << delta
					<< (current[index] != previous[index] ? " *" : "  ");
			}

			std::cout << "\n";
		}

		std::cout.flush();
		drawn = true;

		for (std::size_t index = 0; index < count; ++index) {
			previous[index] = current[index];
			okPrevious[index] = ok[index];
		}

		Sleep(static_cast<DWORD>(intervalMs));
	}
}

// --watch: 实时轮询一组地址，表格显示当前值与相对上次轮询的变化量，用于和屏幕画面对照
static int RunWatch(const std::vector<std::string>& specs, const int intervalMs) {
	const auto addresses = ParseWatchAddresses(specs);
	if (addresses.empty()) {
		std::cerr << "::Main no valid watch address." << std::endl;

		return 1;
	}

	Memory::PMemory memory { };

	try {
		memory = new Memory::Memory();
		memory->Attach(L"onmyoji.exe");
	}
	catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;

		delete memory;

		return 1;
	}

	std::vector<std::string> labels { };
	for (std::size_t index = 0; index < addresses.size(); ++index) {
		std::ostringstream label { };
		label << '[' << std::setw(2) << std::setfill('0') << index << ']';

		labels.push_back(label.str());
	}

	return WatchLoop(memory, addresses, labels, intervalMs);
}

// --autowatch: 自动定位同步变化组并实时监控
// 小游戏每次进入都会重新分配对象导致地址变化, 因此每次运行先做快速三快照,
// 按"B 时刻值完全相同"聚类找出每个数据的所有拷贝, 再直接监控各组代表地址
static int RunAutoWatch(const int intervalMs) {
	Memory::PMemory memory { };

	try {
		memory = new Memory::Memory();
		memory->Attach(L"onmyoji.exe");
	}
	catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;

		delete memory;

		return 1;
	}

	try {
		std::cout << "locating synchronized groups ..." << std::endl;

		const auto regions = FilterWritableRegions(memory->GetRegions());
		const auto triple = TakeTripleSnapshots(memory, regions, 400);

		std::vector<DiffScanCandidate> candidates { };
		CollectFloatCandidates(triple, candidates);

		const auto groups = ClusterByValue(std::move(candidates));
		if (groups.empty()) {
			std::cerr << "no synchronized group found, "
				<< "make sure the mini-game is running with characters moving."
				<< std::endl;

			delete memory;

			return 1;
		}

		const std::size_t limit = std::min<std::size_t>(groups.size(), 12);

		std::vector<std::uintptr_t> addresses { };
		std::vector<std::string> labels { };

		std::cout << "\nlocated " << groups.size() << " group(s), watching top "
			<< limit << ":" << std::endl;

		for (std::size_t index = 0; index < limit; ++index) {
			const auto& group = groups[index];

			addresses.push_back(group.address);
			labels.push_back("G" + std::to_string(index) + "x" + std::to_string(group.copies));

			std::cout << "  [G" << index << "] 0x" << std::hex << group.address << std::dec
				<< "  copies = " << group.copies
				<< ", v1 = " << std::setprecision(9) << group.v1
				<< ", velocity = " << std::setprecision(6) << group.velocity
				<< " /s" << std::endl;
		}

		std::cout << std::endl;

		return WatchLoop(memory, addresses, labels, intervalMs);
	}
	catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;

		delete memory;

		return 1;
	}
}

// ---- track: 抓取单个地址的变化过程 ------------------------------------

// 解析 CE 表格地址: "onmyoji.exe+4E8839C" -> (模块名, 偏移); "7FF6B2B1839C" -> (空模块, 绝对地址)
static bool ParseCtAddress(
	const std::string& spec, std::wstring& module, std::uintptr_t& offset
) {
	const auto plus = spec.find('+');
	if (plus == std::string::npos) {
		module.clear();

		offset = static_cast<std::uintptr_t>(std::strtoull(spec.c_str(), nullptr, 16));
		return offset != 0;
	}

	if (plus == 0 || plus + 1 >= spec.size()) return false;

	module.assign(spec.begin(), spec.begin() + plus);
	offset = static_cast<std::uintptr_t>(std::strtoull(spec.c_str() + plus + 1, nullptr, 16));

	return offset != 0;
}

static std::string WallClockNow(void) {
	const auto now = std::chrono::system_clock::now();
	const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
		now.time_since_epoch()) % 1000;
	const std::time_t seconds = std::chrono::system_clock::to_time_t(now);

	std::tm local { };
	localtime_s(&local, &seconds);

	std::ostringstream stream { };
	stream << std::put_time(&local, "%H:%M:%S")
		<< '.' << std::setw(3) << std::setfill('0') << milliseconds.count();

	return stream.str();
}

// 按 4 字节字输出十六进制, markOffset 处的字加方括号标出目标值
static std::string WordsToHex(
	const std::uint8_t* data, const std::size_t size, const std::size_t markOffset
) {
	std::ostringstream stream { };
	for (std::size_t offset = 0; offset + 4 <= size; offset += 4) {
		std::uint32_t word = 0;
		std::memcpy(&word, data + offset, sizeof(word));

		if (offset == markOffset) stream << '[';
		stream << std::hex << std::setw(8) << std::setfill('0') << word;
		if (offset == markOffset) stream << ']';

		stream << ' ';
	}

	return stream.str();
}

// --track: 抓取单个地址的变化过程
// 地址支持 CE 表格格式 "模块+偏移"(如 onmyoji.exe+4E8839C)或绝对十六进制地址;
// 高频轮询目标 4 字节及其前后上下文窗口, 每次变化记录时间戳/原始字节/float/int32 解释,
// 结果同步写入 track.log 与 track.csv, 用于离线分析加密数值(如对局剩余怪物数)的变化规律
static int RunTrack(const std::string& spec, const int intervalMs) {
	std::wstring module { };
	std::uintptr_t offset = 0;
	if (!ParseCtAddress(spec, module, offset)) {
		std::cerr << "::Main invalid track spec '" << spec
			<< "', expected 'module+hexoffset' or hex address." << std::endl;

		return 1;
	}

	Memory::PMemory memory { };

	try {
		memory = new Memory::Memory();
		memory->Attach(L"onmyoji.exe");
	}
	catch (const std::exception& exception) {
		std::cerr << exception.what() << std::endl;

		delete memory;

		return 1;
	}

	std::uintptr_t address = offset, moduleBase = 0;
	if (!module.empty()) {
		try {
			moduleBase = memory->GetModule(module);
			address = moduleBase + offset;
		}
		catch (const std::exception& exception) {
			std::cerr << exception.what() << std::endl;

			delete memory;

			return 1;
		}
	}

	// 目标 4 字节置于窗口中部, 前后各带一段上下文: 加密值的密钥/关联字段常在邻近位置
	constexpr std::size_t kTargetSize = 4;
	const std::size_t before = std::min<std::size_t>(0x10, address);
	const std::size_t windowSize = before + kTargetSize + 0x0C;
	const std::size_t targetOffset = before;

	std::ofstream log("track.log", std::ios::app);
	std::ofstream csv("track.csv", std::ios::app);
	if (csv) csv << "index,kind,wall,elapsed_ms,raw_old,raw_new,"
		"float_old,float_new,int_old,int_new,context\n";

	{
		std::ostringstream session { };
		session << "==== track " << spec << " target=0x" << std::hex << address
			<< std::dec << " interval=" << intervalMs << "ms"
			<< " window=[0x" << std::hex << (address - before) << ", 0x"
			<< (address - before + windowSize) << ")" << std::dec << " ====";

		std::cout << session.str() << std::endl;
		if (log) log << session.str() << '\n';
	}

	if (moduleBase) std::cout << "module base = 0x" << std::hex << moduleBase
		<< std::dec << std::endl;

	std::vector<std::uint8_t> previous(windowSize, 0), current(windowSize, 0);
	bool hasPrevious = false, previousOk = false;

	const auto startTime = std::chrono::steady_clock::now();
	auto lastEntryTime = startTime;

	std::uint64_t index = 0;

	// 记录一条变化: kind 为 INIT(初始)/VAL(目标 4 字节变化)/CTX(仅上下文变化)
	const auto emitEntry = [&](const char* const kind, const long long elapsedMs) {
		std::uint32_t oldRaw = 0, newRaw = 0;
		std::memcpy(&oldRaw, previous.data() + targetOffset, sizeof(oldRaw));
		std::memcpy(&newRaw, current.data() + targetOffset, sizeof(newRaw));

		float oldFloat = 0.0f, newFloat = 0.0f;
		std::memcpy(&oldFloat, &oldRaw, sizeof(oldFloat));
		std::memcpy(&newFloat, &newRaw, sizeof(newFloat));

		const auto oldInt = static_cast<std::int32_t>(oldRaw);
		const auto newInt = static_cast<std::int32_t>(newRaw);

		const std::string wall = WallClockNow();
		const std::string context = WordsToHex(current.data(), windowSize, targetOffset);
		const std::uint64_t entryIndex = index++;

		std::ostringstream line { };
		line << '#' << entryIndex << " [" << wall << "] +" << elapsedMs << "ms " << kind
			<< "  0x" << std::hex << std::setw(8) << std::setfill('0') << oldRaw
			<< " -> 0x" << std::setw(8) << newRaw << std::setfill(' ') << std::dec
			<< "  f " << oldFloat << " -> " << newFloat
			<< "  i " << oldInt << " -> " << newInt;

		if (kind[0] == 'V') line << "  di " << std::showpos << (newInt - oldInt) << std::noshowpos;

		std::cout << line.str() << "\n    ctx " << context << std::endl;

		if (log) log << line.str() << "\n    ctx " << context << '\n';

		if (csv) csv << entryIndex << ',' << kind << ',' << wall << ',' << elapsedMs
			<< ",0x" << std::hex << std::setw(8) << std::setfill('0') << oldRaw
			<< ",0x" << std::setw(8) << newRaw << std::setfill(' ') << std::dec << ','
			<< oldFloat << ',' << newFloat << ',' << oldInt << ',' << newInt
			<< ',' << context << '\n';
	};

	std::cout << "tracking every " << intervalMs << " ms (Ctrl+C 退出)" << std::endl;

	while (true) {
		const bool ok = memory->ReadRaw(address - before, current.data(), windowSize);

		const auto now = std::chrono::steady_clock::now();
		const auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
			now - startTime).count();

		if (!ok) {
			// 读取失败只在 恢复->失败 边沿记录一次, 恢复后按普通变化处理
			if (previousOk) {
				std::ostringstream line { };
				line << '#' << index++ << " [" << WallClockNow() << "] +"
					<< elapsedMs << "ms ERR  <unreadable>";

				std::cout << line.str() << std::endl;
				if (log) log << line.str() << '\n';
			}

			previousOk = false;

			Sleep(static_cast<DWORD>(intervalMs));
			continue;
		}

		if (!hasPrevious) {
			previous = current;

			hasPrevious = true;
			previousOk = true;

			emitEntry("INIT", elapsedMs);
			lastEntryTime = now;

			Sleep(static_cast<DWORD>(intervalMs));
			continue;
		}

		if (std::memcmp(previous.data(), current.data(), windowSize) != 0) {
			const bool targetChanged = std::memcmp(
				previous.data() + targetOffset, current.data() + targetOffset, kTargetSize
			) != 0;

			emitEntry(targetChanged ? "VAL" : "CTX", elapsedMs);

			previous = current;
			lastEntryTime = now;
		}
		else if (std::chrono::duration_cast<std::chrono::milliseconds>(
			now - lastEntryTime).count() >= 5000) {
			// 心跳: 长时间无变化时每 5s 报告一次当前值, 便于确认仍在抓取
			std::uint32_t raw = 0;
			std::memcpy(&raw, current.data() + targetOffset, sizeof(raw));

			float value = 0.0f;
			std::memcpy(&value, &raw, sizeof(value));

			std::ostringstream line { };
			line << "#  [" << WallClockNow() << "] +" << elapsedMs << "ms HB  0x"
				<< std::hex << std::setw(8) << std::setfill('0') << raw
				<< std::setfill(' ') << std::dec
				<< "  f " << value << "  i " << static_cast<std::int32_t>(raw);

			std::cout << line.str() << std::endl;
			if (log) log << line.str() << '\n';

			lastEntryTime = now;
		}

		Sleep(static_cast<DWORD>(intervalMs));
	}
}

// --ghostwalk/--gwlist 公共选项: --interval=ms --pool=id,id,... --csv=path
static GhostWalk::Options ParseGhostWalkOptions(const std::vector<std::string>& args) {
	GhostWalk::Options options { };

	for (std::size_t index = 1; index < args.size(); ++index) {
		const auto& argument = args[index];

		if (argument.rfind("--interval=", 0) == 0) {
			options.intervalMs = std::max(50, std::atoi(argument.c_str() + 11));
		}
		else if (argument.rfind("--pool=", 0) == 0) {
			options.pool.clear();

			std::stringstream stream(argument.substr(7));
			std::string token { };

			while (std::getline(stream, token, ','))
				if (token.size()) options.pool.push_back(
					std::strtoull(token.c_str(), nullptr, 10));
		}
		else if (argument.rfind("--csv=", 0) == 0) {
			options.csvPath = argument.substr(6);
		}
		else if (argument.rfind("--yvar=", 0) == 0) {
			options.yVar = std::atof(argument.c_str() + 7);
		}
		else if (argument.rfind("--names=", 0) == 0) {
			options.namesPath = argument.substr(8);
		}
		else if (argument == "--freeze") {
			options.freezeOnHit = true;
		}
		else if (argument.rfind("--freeze=", 0) == 0) {
			options.freezeOnHit = argument.substr(9) == "1";
		}
		else if (argument == "--rediscover") {
			options.rediscover = true;
		}
	}

	if (options.pool.empty()) {
		// 默认式神池: 玩家配置 baigui_hero_full
		for (const auto id : { 384, 593, 514, 515, 516, 518,
			520, 419, 405, 407, 404, 406, 611 }) options.pool.push_back(id);
	}

	return options;
}

int main(const int argc, char* argv[]) {
	// 源码字面量为 UTF-8 (/utf-8 编译), 控制台输出码页切到 UTF-8 避免中文乱码
	SetConsoleOutputCP(CP_UTF8);

	// 关闭 QuickEdit: 鼠标点击窗口会进入选择态并阻塞 stdout,
	// 表现为工具卡住、按任意键才继续
	if (const HANDLE console = GetStdHandle(STD_OUTPUT_HANDLE);
		console != INVALID_HANDLE_VALUE) {
		DWORD mode = 0;
		if (GetConsoleMode(console, &mode)) SetConsoleMode(console,
			(mode | ENABLE_EXTENDED_FLAGS) & ~ENABLE_QUICK_EDIT_MODE);
	}

	const std::vector<std::string> args(argv + 1, argv + argc);

	if (!args.empty() && args[0] == "--ghostwalk") return GhostWalk::RunWatch(
		ParseGhostWalkOptions(args));

	if (!args.empty() && args[0] == "--gwlist") return GhostWalk::RunWalkList(
		ParseGhostWalkOptions(args));

	if (!args.empty() && args[0] == "--gwstate") return GhostWalk::RunStateChase(
		ParseGhostWalkOptions(args));

	if (!args.empty() && args[0] == "--gwparse") return GhostWalk::RunGwParse(
		ParseGhostWalkOptions(args));

	if (!args.empty() && args[0] == "--gwfind") return GhostWalk::RunGwFind(
		ParseGhostWalkOptions(args));

	if (!args.empty() && args[0] == "--gwwatch") return GhostWalk::RunGwWatch(
		ParseGhostWalkOptions(args));

	if (!args.empty() && args[0] == "--gwtype") return GhostWalk::RunGwType(
		ParseGhostWalkOptions(args));

	if (!args.empty() && args[0] == "--diffscan") return RunDiffScan();

	if (!args.empty() && args[0] == "--refs" && args.size() > 1) return RunRefs(
		static_cast<std::uintptr_t>(std::strtoull(args[1].c_str(), nullptr, 16))
	);

	if (!args.empty() && args[0] == "--dump" && args.size() > 2) return RunDump(
		static_cast<std::uintptr_t>(std::strtoull(args[1].c_str(), nullptr, 16)),
		static_cast<std::size_t>(std::strtoull(args[2].c_str(), nullptr, 16))
	);

	if (!args.empty() && args[0] == "--track" && args.size() > 1) {
		int intervalMs = 25;

		for (std::size_t index = 2; index < args.size(); ++index)
			if (args[index].rfind("--interval=", 0) == 0)
				intervalMs = std::max(5, std::atoi(args[index].c_str() + 11));

		return RunTrack(args[1], intervalMs);
	}

	if (!args.empty() && args[0] == "--watch" && args.size() > 1) {
		int intervalMs = 250;
		std::vector<std::string> specs { };

		for (std::size_t index = 1; index < args.size(); ++index) {
			if (args[index].rfind("--interval=", 0) == 0)
				intervalMs = std::max(50, std::atoi(args[index].c_str() + 11));
			else specs.push_back(args[index]);
		}

		return RunWatch(specs, intervalMs);
	}

	if (!args.empty() && args[0] == "--autowatch") {
		int intervalMs = 250;

		for (std::size_t index = 1; index < args.size(); ++index)
			if (args[index].rfind("--interval=", 0) == 0)
				intervalMs = std::max(50, std::atoi(args[index].c_str() + 11));

		return RunAutoWatch(intervalMs);
	}

	return RunRecon();
}
