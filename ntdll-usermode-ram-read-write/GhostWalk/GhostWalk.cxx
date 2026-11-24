/*
    File GhostWalk.cxx
    yys_ghostwalk_reader.py 的 C++/ntdll 移植: 百鬼夜行运行时只读内存探针

    原理 (与 Python 版一致):
      - 游戏逻辑为 CPython 2.7 (NeoX 引擎), 坐标以 PyFloatObject
        ([refcnt 8][ob_type 8][double 8]) 存储,
        式神 ID 以 PyIntObject ([refcnt 8][ob_type 8][int32 4][padding 4]) 存储
      - 同一类型对象的 ob_type 指针相同:
        先用已知式神 ID / 双精度候选字节模式做直方图识别 PyFloat_Type / PyInt_Type
        指针, 再按字节模式 (memchr 加速) 批量定位对象, 不硬编码任何地址
      - 类型指针合理性过滤: CPython 类型对象是模块静态数据, 指针必须落在
        onmyoji.exe / python27.dll 映像范围内, 剔除数据巧合造成的假指针
      - watch: 逐帧差分, x 持续递减 (屏幕上右->左) 且速度稳定者为行走式神,
        归属坐标对象前后 0x300 字节内最近的式神 ID 整型对象
      - gwlist: 转储 16KB 滑窗内含 >=5 个不同池内 ID 的缓冲区 (对应
        BaiGuiYeXingMember.bgyx_onGetWalkListAsw 下发的行走列表);
        未识别 PyInt_Type 时回退为原始 int32 数组匹配
*/

#include "GhostWalk.hxx"
#include "Memory/Memory.hxx"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <unordered_map>
#include <vector>

namespace GhostWalk {
    namespace {
        using Memory::PMemory;

        // CPython 2.7 pymalloc arena 约为 1MB 的 MEM_PRIVATE 区域,
        // 全部 PyFloatObject/PyIntObject 都住在小区域里, 下限必须足够低
        constexpr std::size_t kMinRegionBytes = 16ull * 1024;
        constexpr std::size_t kMaxRegionBytes = 256ull * 1024 * 1024;
        constexpr std::size_t kQualifyHeadBytes = 64ull * 1024 * 1024;
        constexpr std::size_t kDumpLimit = 40;
        constexpr std::size_t kNearestIntRadius = 128;
        constexpr std::size_t kHistoryMax = 10;
        constexpr std::size_t kFloatTypeMinCount = 100;

        // 百鬼夜行特征标识: 命中任一即认为该内存区域与 GhostWalk 相关
        const char* const kQualMarkers[] = {
            "GhostWalk", "ghostwalk", "GHOSTWALK",
            "BaiGuiYeXing", "baigui", "BAIGUI", "bgyx", "BGYX",
        };

        struct Region {
            std::uintptr_t base;
            std::size_t size;
        };

        struct ModuleRange {
            std::uintptr_t base;
            std::size_t size;
        };

        std::uint64_t U64At(const std::uint8_t* data, const std::size_t offset) {
            std::uint64_t value = 0;
            std::memcpy(&value, data + offset, sizeof(value));
            return value;
        }

        std::uint32_t U32At(const std::uint8_t* data, const std::size_t offset) {
            std::uint32_t value = 0;
            std::memcpy(&value, data + offset, sizeof(value));
            return value;
        }

        double F64At(const std::uint8_t* data, const std::size_t offset) {
            double value = 0.0;
            std::memcpy(&value, data + offset, sizeof(value));
            return value;
        }

        // 读取整个区域, 8MB 分块; 失败时返回已读部分 (与 Python 版容错一致)
        std::vector<std::uint8_t> ReadRegion(const PMemory memory, const Region& region) {
            std::vector<std::uint8_t> data;
            data.reserve(region.size);

            constexpr std::size_t kChunk = 8ull * 1024 * 1024;
            for (std::size_t offset = 0; offset < region.size; offset += kChunk) {
                const auto size = std::min(kChunk, region.size - offset);
                std::vector<std::uint8_t> chunk(size);

                if (!memory->ReadRaw(region.base + offset, chunk.data(), size)) break;
                data.insert(data.end(), chunk.begin(), chunk.end());
            }

            return data;
        }

        bool Qualify(const std::vector<std::uint8_t>& data) {
            for (const char* const marker : kQualMarkers) {
                const auto* const first = reinterpret_cast<const std::uint8_t*>(marker);
                const auto* const last = first + std::strlen(marker);

                if (std::search(data.begin(), data.end(), first, last) != data.end()) return true;
            }

            return false;
        }

        // 可读 MEM_PRIVATE / MEM_MAPPED 提交区域, 2MB..256MB
        std::vector<Region> CollectReadableRegions(const PMemory memory) {
            constexpr DWORD kReadable =
                PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
                PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

            std::vector<Region> regions { };
            for (const auto& info : memory->GetRegions()) {
                if (info.State != MEM_COMMIT) continue;
                if (info.Type != MEM_PRIVATE && info.Type != MEM_MAPPED) continue;
                if (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;
                if (!(info.Protect & kReadable)) continue;

                const auto size = static_cast<std::size_t>(info.RegionSize);
                if (size < kMinRegionBytes || size > kMaxRegionBytes) continue;

                regions.push_back({
                    reinterpret_cast<std::uintptr_t>(info.BaseAddress), size
                });
            }

            return regions;
        }

        // 特征限定: 先读前 64MB; 未命中的大区域再流式扫描剩余部分,
        // 避免漏掉标识位于区域后半段的情况 (Python 版全量扫描可找到 76 个标识区域)
        // 流式扫描每 1GB 打印进度, 避免长时间静默被误认为卡死
        std::vector<Region> CollectQualifiedRegions(const PMemory memory) {
            const auto all = CollectReadableRegions(memory);

            std::vector<Region> qualified { };
            constexpr std::size_t kChunk = 8ull * 1024 * 1024;

            std::size_t scannedBytes = 0, nextProgress = 1024ull * 1024 * 1024;

            for (const auto& region : all) {
                const auto head = ReadRegion(memory, {
                    region.base, std::min(region.size, kQualifyHeadBytes)
                });
                scannedBytes += head.size();

                if (Qualify(head)) {
                    qualified.push_back(region);
                    continue;
                }

                if (region.size <= kQualifyHeadBytes) continue;

                bool hit = false;
                for (std::size_t offset = kQualifyHeadBytes;
                    offset < region.size && !hit; offset += kChunk) {
                    const auto size = std::min(kChunk, region.size - offset);
                    std::vector<std::uint8_t> chunk(size);

                    if (!memory->ReadRaw(region.base + offset, chunk.data(), size)) break;
                    scannedBytes += size;
                    hit = Qualify(chunk);

                    if (scannedBytes >= nextProgress) {
                        std::cout << "    [限定] 已读 " << (scannedBytes / 1024 / 1024)
                            << " MB, 命中区域 " << qualified.size() << std::endl;
                        nextProgress += 1024ull * 1024 * 1024;
                    }
                }

                if (hit) qualified.push_back(region);
            }

            std::cout << "    [限定] 共读 " << (scannedBytes / 1024 / 1024)
                << " MB, 命中区域 " << qualified.size() << std::endl;

            return qualified;
        }

        // 定位 needle 全部出现位置 (memchr 跳跃), 每处回调偏移
        template<typename Fn>
        void FindAll(
            const std::uint8_t* data, const std::size_t size,
            const std::uint8_t* needle, const std::size_t needleSize, Fn&& callback
        ) {
            if (size < needleSize) return;

            const auto last = size - needleSize;
            const auto firstByte = needle[0];

            std::size_t offset = 0;
            while (offset <= last) {
                const auto* const hit = static_cast<const std::uint8_t*>(
                    std::memchr(data + offset, firstByte, last - offset + 1));
                if (!hit) break;

                offset = static_cast<std::size_t>(hit - data);

                if (needleSize == 1 || std::memcmp(data + offset, needle, needleSize) == 0)
                    callback(offset);

                ++offset;
            }
        }

        std::size_t ImageSize(const PMemory memory, const std::uintptr_t base) {
            const auto ntHeader = base + memory->Read<std::uint32_t>(base + 0x3C);
            if (memory->Read<std::uint32_t>(ntHeader) != 0x00004550) return 0;

            return memory->Read<std::uint32_t>(ntHeader + 0x18 + 0x38); // SizeOfImage
        }

        // CPython 类型对象 (PyFloat_Type/PyInt_Type) 是模块静态数据:
        // ob_type 指针必须落在 onmyoji.exe / python27.dll 映像范围内
        std::vector<ModuleRange> CollectModuleRanges(const PMemory memory) {
            std::vector<ModuleRange> ranges { };

            for (const auto name : { L"onmyoji.exe", L"python27.dll" }) {
                try {
                    const auto base = memory->GetModule(name);
                    const auto size = ImageSize(memory, base);

                    if (size) ranges.push_back({ base, size });
                }
                catch (const std::exception&) { /* 模块缺失则跳过 */ }
            }

            return ranges;
        }

        bool InRanges(const std::vector<ModuleRange>& ranges, const std::uintptr_t pointer) {
            for (const auto& range : ranges)
                if (pointer >= range.base && pointer < range.base + range.size) return true;

            return false;
        }

        // 取直方图中计数最高且达到 minCount、且落在模块映像内的指针
        std::uintptr_t BestPointer(
            const std::unordered_map<std::uint64_t, std::size_t>& histogram,
            const std::vector<ModuleRange>& moduleRanges,
            const std::size_t minCount
        ) {
            std::uintptr_t best = 0;
            std::size_t bestCount = 0;

            for (const auto& entry : histogram) {
                if (entry.second < minCount) continue;
                if (!InRanges(moduleRanges, entry.first)) continue;
                if (entry.second > bestCount) {
                    best = entry.first;
                    bestCount = entry.second;
                }
            }

            return best;
        }

        // PyInt_Type: 用池内 ID 的 4 字节 ival 定位 (ob_type 指针在 ival-8) 做直方图
        // PyFloat_Type: 用双精度候选字节模式 (exp 1008..1039, 正数) 做直方图
        // 直方图跨区域累计 (单个 1MB arena 内命中数有限), 扫完取最优;
        // poolIntHits 返回全程发现的"池内 ID 8 对齐出现"总数, 供失败时区分原因
        bool DiscoverTypePointers(
            const PMemory memory,
            const std::vector<Region>& regions,
            const std::vector<std::uint64_t>& pool,
            const bool needFloat, const bool needInt,
            std::uintptr_t& pyFloatType, std::uintptr_t& pyIntType,
            std::size_t& poolIntHits
        ) {
            pyFloatType = 0;
            pyIntType = 0;
            poolIntHits = 0;

            const auto moduleRanges = CollectModuleRanges(memory);

            std::unordered_map<std::uint64_t, std::size_t> intHistogram { };
            std::unordered_map<std::uint64_t, std::size_t> floatHistogram { };

            for (const auto& region : regions) {
                const auto data = ReadRegion(memory, region);
                if (data.size() < 1024 * 1024 / 8) continue;

                if (!pyIntType) {
                    for (const auto id : pool) {
                        std::uint8_t needle[4];
                        std::memcpy(needle, &id, sizeof(needle));

                        FindAll(data.data(), data.size(), needle, sizeof(needle),
                            [&](const std::size_t offset) {
                                if (offset < 8 || ((region.base + offset) & 7) != 0) return;
                                ++intHistogram[U64At(data.data(), offset - 8)];
                                ++poolIntHits;
                            });
                    }

                    pyIntType = BestPointer(intHistogram, moduleRanges, 3);
                }

                if (!pyFloatType) {
                    for (std::size_t offset = 0; offset + 8 <= data.size(); offset += 8) {
                        // LE double: b6 = exp 低 4 位, b7 = 符号 + exp 高 7 位
                        if (data[offset + 6] > 0x3F) continue;
                        if (data[offset + 7] != 0x3F && data[offset + 7] != 0x40) continue;

                        const auto value = F64At(data.data(), offset);
                        if (!std::isfinite(value) || value < 0.05 || value > 10000.0) continue;

                        if (offset >= 8) ++floatHistogram[U64At(data.data(), offset - 8)];
                    }

                    pyFloatType = BestPointer(floatHistogram, moduleRanges,
                        kFloatTypeMinCount);
                }

                if ((!needFloat || pyFloatType) && (!needInt || pyIntType)) break;
            }

            return (!needFloat || pyFloatType) && (!needInt || pyIntType);
        }

        struct RegionObjects {
            std::unordered_map<std::uintptr_t, double> floats;      // double 地址 -> 值
            std::unordered_map<std::uintptr_t, std::uint64_t> ints; // ival 地址 -> 值
            std::unordered_map<std::uintptr_t, float> floats32;     // 引擎 float32 地址 -> 值
        };

        // 重建单个区域的 PyFloatObject / PyIntObject 对象图 + 引擎 float32 候选
        RegionObjects ScanRegionObjects(
            const PMemory memory, const Region& region,
            const std::uint8_t* ptr8f, const std::uint8_t* ptr8i, const bool withInts
        ) {
            RegionObjects objects { };
            const auto data = ReadRegion(memory, region);

            FindAll(data.data(), data.size(), ptr8f, 8,
                [&](const std::size_t typeOffset) {
                    constexpr std::size_t kValueOffset = 8; // double 跟在 ob_type 后
                    if (typeOffset + kValueOffset + 8 > data.size()) return;

                    const auto value = F64At(data.data(), typeOffset + kValueOffset);
                    if (!std::isfinite(value) || value < 0.05 || value > 10000.0) return;

                    objects.floats[region.base + typeOffset + kValueOffset] = value;
                });

            if (withInts) {
                FindAll(data.data(), data.size(), ptr8i, 8,
                    [&](const std::size_t typeOffset) {
                        constexpr std::size_t kValueOffset = 8; // int32 ival 跟在 ob_type 后
                        if (typeOffset + kValueOffset + 4 > data.size()) return;

                        const auto value = U32At(data.data(), typeOffset + kValueOffset);
                        if (value < 100 || value > 2000) return;

                        objects.ints[region.base + typeOffset + kValueOffset] = value;
                    });
            }

            // 引擎侧 float32 收集移至 F 通道差分路径 (见 RunWatch), 此处不再重复扫描
            return objects;
        }

        struct MoverRow {
            char channel;          // 'D' = PyFloatObject double, 'F' = 引擎 float32
            std::string time;      // 本帧观测时间
            double x;
            float y;               // 邻居 +4 字节 (Y 坐标)
            double yRange;         // Y 轴历史变化幅度 (道具上下移动时大)
            bool item;             // true = 道具(上下移动), false = 式神(水平直线)
            std::uintptr_t address;
            std::uint64_t heroId;
            std::string heroName;
            bool hasHero;
            bool poolMatch;
            double vx;
            std::size_t samples;
            std::size_t entityObs = 0; // 匹配到的实体被观测帧数 (噪声过滤用)
            std::size_t entityIndex = 0; // 匹配到的实体编号 (1 起)
        };

        // 坐标对象前后 0x300 字节内最近的式神 ID: 优先取官方表内存在的 ID
        const std::uint64_t* NearestHero(
            const std::vector<std::uintptr_t>& sortedKeys,
            const std::unordered_map<std::uintptr_t, std::uint64_t>& ints,
            const std::map<std::uint64_t, std::string>& heroNames,
            const std::uintptr_t address
        ) {
            if (sortedKeys.empty()) return nullptr;

            const auto beginIt = std::lower_bound(sortedKeys.begin(), sortedKeys.end(),
                address - kNearestIntRadius);
            const auto endIt = std::upper_bound(sortedKeys.begin(), sortedKeys.end(),
                address + kNearestIntRadius);

            const std::uint64_t* bestAny = nullptr;
            const std::uint64_t* bestValid = nullptr;
            std::uintptr_t bestAnyDistance = 0, bestValidDistance = 0;

            for (auto it = beginIt; it != endIt; ++it) {
                const auto distance = *it > address ? *it - address : address - *it;

                if (!bestAny || distance < bestAnyDistance) {
                    bestAny = &ints.at(*it);
                    bestAnyDistance = distance;
                }

                if (!heroNames.empty() && heroNames.count(*it)
                    && (!bestValid || distance < bestValidDistance)) {
                    bestValid = &ints.at(*it);
                    bestValidDistance = distance;
                }
            }

            // 官方表内 ID 优先; 表缺失时退回任意最近 ID
            return bestValid ? bestValid : bestAny;
        }

        std::string WallClockNow(void) {
            const auto now = std::chrono::system_clock::now();
            const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) % 1000;
            const std::time_t seconds = std::chrono::system_clock::to_time_t(now);

            std::tm local { };
            localtime_s(&local, &seconds);

            std::ostringstream stream { };
            stream << std::put_time(&local, "%H:%M:%S");

            return stream.str();
        }

        // 类型指针缓存: PyFloat_Type/PyInt_Type 是模块静态地址,
        // 同一次游戏启动内不变, 缓存后跳过全量识别 (识别需读取全部标识区域, 较慢)
        constexpr const char* kTypeCacheFile = "gw_types.txt";

        bool LoadTypeCache(std::uintptr_t& pyFloatType, std::uintptr_t& pyIntType) {
            std::ifstream file(kTypeCacheFile);
            if (!file) return false;

            std::string floatLine, intLine;
            if (!std::getline(file, floatLine) || !std::getline(file, intLine)) return false;

            const auto pFloat = std::strtoull(floatLine.c_str(), nullptr, 16);
            const auto pInt = std::strtoull(intLine.c_str(), nullptr, 16);

            if (!pFloat || !pInt) return false;

            pyFloatType = pFloat;
            pyIntType = pInt;

            return true;
        }

        void SaveTypeCache(const std::uintptr_t pyFloatType, const std::uintptr_t pyIntType) {
            std::ofstream file(kTypeCacheFile, std::ios::trunc);
            if (!file) return;

            file << std::hex << pyFloatType << "\n" << pyIntType << std::endl;
        }

        // 加载官方式神表 (shishen.json): "200":{"id":200,"name":"桃花妖",...}
        std::map<std::uint64_t, std::string> LoadHeroNames(const std::string& path) {
            std::map<std::uint64_t, std::string> names;

            std::ifstream file(path, std::ios::binary);
            if (!file) return names;

            std::string content((std::istreambuf_iterator<char>(file)),
                std::istreambuf_iterator<char>());

            const std::regex re(
                R"rx("(\d+)"\s*:\s*\{\s*"id"\s*:\s*\d+\s*,\s*"name"\s*:\s*"([^"]*)")rx");

            for (auto it = std::sregex_iterator(content.begin(), content.end(), re);
                it != std::sregex_iterator(); ++it) {
                names[std::strtoull((*it)[1].str().c_str(), nullptr, 10)] = (*it)[2].str();
            }

            return names;
        }

        // 原始 int32 归属: 读取坐标对象前后各 0x300 字节, 取最近的
        // 官方表内式神 ID (100..2000 值域) -- 表外整数视为检索噪声
        std::uint64_t AttributeHeroRaw(
            const PMemory memory, const std::uintptr_t address,
            const std::map<std::uint64_t, std::string>& heroNames,
            bool& found
        ) {
            found = false;

            std::uint64_t bestId = 0;
            std::uintptr_t bestDistance = 0;

            const auto probe = [&](const std::uintptr_t base, const std::size_t size) {
                const auto data = memory->ReadBytes(base, size);
                if (data.size() < 4) return;

                for (std::size_t offset = 0; offset + 4 <= data.size(); offset += 4) {
                    if ((base + offset) & 3) continue; // 4 对齐

                    const auto value = U32At(data.data(), offset);
                    if (value < 100 || value > 2000) continue;
                    if (!heroNames.empty() && !heroNames.count(value)) continue;

                    const auto target = base + offset;
                    const auto distance = target > address
                        ? target - address : address - target;
                    if (distance > kNearestIntRadius) continue;

                    if (!found || distance < bestDistance) {
                        bestId = value;
                        bestDistance = distance;
                        found = true;
                    }
                }
            };

            // 分两段读, 避免跨区域导致整体失败
            probe(address - kNearestIntRadius, kNearestIntRadius);
            probe(address, kNearestIntRadius + 4);

            return bestId;
        }
    }

    // --ghostwalk: 逐帧差分追踪右->左移动的坐标对象
    int RunWatch(const Options& options) {
        PMemory memory { };

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
            std::cout << "[*] 目标 onmyoji.exe, 只读模式 (NtOpenProcess 无写权限)" << std::endl;

            // 官方式神 ID->名称表 (shishen.json 以官方数据为准)
            std::map<std::uint64_t, std::string> heroNames;
            {
                const char* const candidates[] = {
                    options.namesPath.c_str(),
                    "D:\\CppProduct\\ntdll-usermode-ram-read-write\\ntdll-usermode-ram-read-write\\shishen.json",
                };

                for (const auto* path : candidates) {
                    heroNames = LoadHeroNames(path);
                    if (!heroNames.empty()) {
                        std::cout << "[*] 式神名称表: " << path << " ("
                            << heroNames.size() << " 条)" << std::endl;
                        break;
                    }
                }

                if (heroNames.empty()) std::cout
                    << "[*] 未找到 shishen.json, ID 不做官方表校验" << std::endl;
            }
            std::cout << "[*] 第一遍: 枚举区域并识别 CPython 类型指针 ..." << std::endl;

            const auto qualified = CollectQualifiedRegions(memory);
            std::cout << "[*] 含百鬼标识区域: " << qualified.size() << std::endl;

            if (qualified.empty()) {
                std::cerr << "[!] 未找到含 GhostWalk/bgyx 标识的区域,"
                    " 请先进入百鬼夜行玩法再运行" << std::endl;

                delete memory;

                return 1;
            }

            std::uintptr_t pyFloatType = 0, pyIntType = 0;
            std::size_t poolIntHits = 0;
            bool fromCache = false;

            if (!options.rediscover && LoadTypeCache(pyFloatType, pyIntType)) {
                fromCache = true;

                std::cout << "[*] 使用缓存类型指针: PyFloat=0x" << std::hex << pyFloatType
                    << " PyInt=0x" << pyIntType << std::dec
                    << " (--rediscover 重新识别)" << std::endl;
            }
            else {
                DiscoverTypePointers(memory, qualified, options.pool,
                    true, true, pyFloatType, pyIntType, poolIntHits);

                if (pyFloatType) SaveTypeCache(pyFloatType, pyIntType);
            }

            // PyFloat_Type 必需; PyInt_Type 缺失时回退原始 int32 归属, 不中止
            if (!pyFloatType) {
                if (poolIntHits == 0) std::cerr << "[!] 区域内未发现任何池内式神 ID 对象,"
                    " 行走列表尚未加载 -- 请在夜行阶段(式神开始行走)时再试" << std::endl;
                else std::cerr << "[!] 未能识别 PyFloat_Type"
                    << " (池ID命中=" << poolIntHits << ")" << std::endl;

                delete memory;

                return 1;
            }

            const bool havePyInt = pyIntType != 0;
            if (havePyInt) std::cout << "[*] PyFloat_Type=0x" << std::hex << pyFloatType
                << "  PyInt_Type=0x" << pyIntType << std::dec << std::endl;
            else std::cout << "[*] PyFloat_Type=0x" << std::hex << pyFloatType << std::dec
                << "  PyInt_Type 未识别, ID 归属使用原始 int32 局部匹配" << std::endl;

            std::uint8_t ptr8f[8], ptr8i[8] { };
            std::memcpy(ptr8f, &pyFloatType, sizeof(ptr8f));
            if (havePyInt) std::memcpy(ptr8i, &pyIntType, sizeof(ptr8i));

            // D 通道区域: 标识区域 (Python 对象); F 通道区域: 全部可写区域 (引擎实体)
            // 引擎实体坐标不在标识区域内, F 通道必须覆盖全部可写内存
            const auto& tickRegions = qualified;

            std::vector<Region> f32Regions;
            {
                constexpr DWORD kWritable = PAGE_READWRITE | PAGE_WRITECOPY
                    | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

                std::size_t f32Total = 0;
                for (const auto& info : memory->GetRegions()) {
                    if (info.State != MEM_COMMIT) continue;
                    if (info.Type != MEM_PRIVATE && info.Type != MEM_MAPPED) continue;
                    if (!(info.Protect & kWritable)) continue;
                    if (info.Protect & (PAGE_GUARD | PAGE_NOACCESS)) continue;

                    const auto size = static_cast<std::size_t>(info.RegionSize);
                    if (size < kMinRegionBytes || size > 64ull * 1024 * 1024) continue;

                    f32Regions.push_back({
                        reinterpret_cast<std::uintptr_t>(info.BaseAddress), size
                    });
                    f32Total += size;
                }

                std::cout << "[*] F 通道可写区域: " << f32Regions.size() << " 个, 共 "
                    << (f32Total / 1024 / 1024) << " MB (每帧 memcmp 差分, 仅扫变化区域)"
                    << std::endl;
            }

            std::ofstream csv;
            if (!options.csvPath.empty()) {
                csv.open(options.csvPath, std::ios::trunc);
                if (csv) csv << "time,channel,addr,hero_id,hero_name,pool_match,x,vx_units_per_s,samples,y_range,item,entity_obs\n";
            }

            std::cout << "[*] 开始逐帧追踪, Ctrl+C 退出. (vx<0 即 x 递减 = 屏幕上右->左)"
                << std::endl << std::endl;

            std::unordered_map<std::uintptr_t, double> previous;
            std::unordered_map<std::uintptr_t, std::deque<std::pair<double, double>>> history;
            std::unordered_map<std::uintptr_t, std::deque<float>> history32;
            std::unordered_map<std::uintptr_t, std::deque<float>> history32y; // Y 轴历史
            std::unordered_map<std::uintptr_t, std::vector<std::uint8_t>> f32Prev;

            auto previousScan = std::chrono::steady_clock::now();
            std::uint64_t tick = 0;

            // D 通道状态持久化 (D 通道降频扫描, 每 3 帧一次, 省去 250MB/帧)
            std::unordered_map<std::uintptr_t, double> current;
            std::unordered_map<std::uintptr_t, std::uint64_t> intsAll;
            std::size_t lastDCount = 0;

            // 实体注册表: 一轮百鬼夜行共 36 只式神 (可重复), 按位置连续性跨帧跟踪
            // 预测 x = lastX + vx*dt; 连续缺席 kMissLimit 帧 => 已离场
            struct Entity {
                double lastX = 0.0, lastY = 0.0, vx = 0.0;
                std::uint64_t heroId = 0;
                std::string heroName;
                bool hasHero = false;
                std::size_t observations = 0;
                std::size_t missed = 0;
                bool finished = false;
                std::string firstTime, lastTime;
            };

            std::vector<Entity> entities;
            constexpr double kMatchRadius = 30.0;
            constexpr std::size_t kMissLimit = 3;

            while (true) {
                const auto scanStart = std::chrono::steady_clock::now();
                const auto dt = std::chrono::duration<double>(scanStart - previousScan).count();
                previousScan = scanStart;

                const bool dTick = (tick % 3 == 1) || tick <= 2;

                if (dTick) {
                    current.clear();
                    intsAll.clear();

                    for (const auto& region : tickRegions) {
                        const auto objects = ScanRegionObjects(
                            memory, region, ptr8f, ptr8i, true);
                        current.insert(objects.floats.begin(), objects.floats.end());
                        intsAll.insert(objects.ints.begin(), objects.ints.end());
                    }

                    lastDCount = current.size();
                }

                std::vector<std::uintptr_t> intKeys;
                intKeys.reserve(intsAll.size());
                for (const auto& entry : intsAll) intKeys.push_back(entry.first);
                std::sort(intKeys.begin(), intKeys.end());

                std::vector<MoverRow> rows { };

                // 通道 F: 快照差分 -- 与上一帧快照字节逐点比较, 不建中间大表
                std::size_t f32Changed = 0;
                for (const auto& region : f32Regions) {
                    auto data = ReadRegion(memory, region);
                    if (data.size() < 8) continue;

                    auto& prev = f32Prev[region.base];
                    if (prev.size() != data.size()) {
                        // 首帧或区域尺寸变化: 仅建立快照, 不扫描
                        prev = std::move(data);
                        continue;
                    }
                    if (std::memcmp(prev.data(), data.data(), data.size()) == 0) continue;

                    for (std::size_t offset = 0; offset + 8 <= data.size(); offset += 4) {
                        float now = 0.0f, before = 0.0f;
                        std::memcpy(&now, data.data() + offset, sizeof(now));
                        std::memcpy(&before, prev.data() + offset, sizeof(before));
                        if (!std::isfinite(now) || !std::isfinite(before)) continue;
                        if (now < -2000.0f || now > 20000.0f) continue;
                        if (now == 0.0f && before == 0.0f) continue;

                        // 坐标对过滤: 邻居 +4 字节也应是有限 float32 (x/y 相邻存储)
                        float neighbor = 0.0f;
                        std::memcpy(&neighbor, data.data() + offset + 4, sizeof(neighbor));
                        if (!std::isfinite(neighbor) || neighbor == 0.0f
                            || neighbor < -2000.0f || neighbor > 20000.0f) continue;

                        const auto delta = static_cast<double>(now) - before;
                        if (delta >= -0.02 || delta <= -300.0) continue; // x 递减 = 右->左

                        auto& series = history32[region.base + offset];
                        series.push_back(static_cast<float>(delta));
                        while (series.size() > kHistoryMax) series.pop_front();

                        // Y 轴历史 (邻居 +4): 道具上下移动时变化大, 式神水平行走时恒定
                        auto& yseries = history32y[region.base + offset];
                        yseries.push_back(neighbor);
                        while (yseries.size() > kHistoryMax) yseries.pop_front();

                        // >=2 样本即写 CSV (帧间隔大, 回合内样本珍贵); >=4 才打印
                        if (series.size() < 2) continue;

                        double deltaSum = 0.0, mn = 1e30, mx = 0.0;
                        for (const auto sample : series) {
                            deltaSum += sample;

                            const auto magnitude = std::abs(static_cast<double>(sample));
                            mn = std::min(mn, magnitude);
                            mx = std::max(mx, magnitude);
                        }

                        const auto vx = (deltaSum / dt) / static_cast<double>(series.size());

                        // 速度下限对所有样本生效: 剔除行走列表进度值 (vx≈-0.1 的
                        // 全体同步递减数组) 与相机漂移, 保留真实式神位移 (vx≈-3~-12)
                        if (vx > -1.0 || vx < -3000.0) continue;

                        // 一致性过滤仅对 >=4 样本生效
                        if (series.size() >= 4 && mx > 2.0 * mn + 0.05) continue;

                        double yMin = 1e30, yMax = -1e30;
                        for (const auto y : yseries) {
                            yMin = std::min(yMin, static_cast<double>(y));
                            yMax = std::max(yMax, static_cast<double>(y));
                        }

                        MoverRow row { };
                        row.channel = 'F';
                        row.x = now;
                        row.y = neighbor;
                        row.yRange = yMax - yMin;
                        row.item = row.yRange > options.yVar; // 上下移动 = 道具
                        row.address = region.base + offset;
                        row.vx = vx;
                        row.samples = series.size();
                        row.time = WallClockNow();

                        // 屏幕坐标过滤: 剔除世界坐标/相机 (x≈9390/19262 等)
                        if (row.x < -500.0 || row.x > 2000.0) continue;

                        if (const auto hero = NearestHero(intKeys, intsAll, heroNames,row.address)) {
                            row.hasHero = true;
                            row.heroId = *hero;
                        }
                        else {
                            bool found = false;
                            row.heroId = AttributeHeroRaw(memory, row.address, heroNames, found);
                            row.hasHero = found;
                        }

                        if (row.hasHero) {
                            row.poolMatch = std::find(
                                options.pool.begin(), options.pool.end(), row.heroId
                            ) != options.pool.end();

                            const auto known = heroNames.find(row.heroId);
                            if (known != heroNames.end()) row.heroName = known->second;
                        }

                        rows.push_back(row);
                    }

                    prev = std::move(data);
                    ++f32Changed;
                }

                // 实体注册表匹配: 预测 x = lastX + vx*dt (新实体首帧不预测)
                std::vector<char> matched(entities.size(), 0);

                for (auto& row : rows) {
                    if (row.channel != 'F' || row.item) continue;

                    std::size_t best = SIZE_MAX;
                    double bestDistance = 0.0;

                    for (std::size_t index = 0; index < entities.size(); ++index) {
                        const auto& entity = entities[index];
                        if (entity.finished) continue;

                        const auto predicted = entity.lastX
                            + (entity.observations > 1 ? entity.vx * dt : 0.0);
                        const auto distance = std::abs(row.x - predicted);
                        if (distance < kMatchRadius
                            && (best == SIZE_MAX || distance < bestDistance)) {
                            best = index;
                            bestDistance = distance;
                        }
                    }

                    if (best == SIZE_MAX) {
                        Entity entity;
                        entity.lastX = row.x;
                        entity.lastY = row.y;
                        entity.vx = row.vx;
                        entity.heroId = row.heroId;
                        entity.heroName = row.heroName;
                        entity.hasHero = row.hasHero;
                        entity.observations = 1;
                        entity.firstTime = row.time;
                        entity.lastTime = row.time;

                        entities.push_back(std::move(entity));
                        matched.push_back(1); // 新实体本帧已观测, 保持 matched 与 entities 同长

                        row.entityIndex = entities.size();
                        row.entityObs = 1;

                        std::cout << "  [新入场] 实体#" << entities.size()
                            << " @x=" << std::fixed << std::setprecision(1) << row.x
                            << (row.hasHero ? " ID=" + std::to_string(row.heroId)
                                + (row.heroName.empty() ? "" : "(" + row.heroName + ")") : "")
                            << std::endl;
                        continue;
                    }

                    auto& entity = entities[best];
                    if (dt > 0.0) {
                        const auto instantVx = (row.x - entity.lastX) / dt;
                        entity.vx = entity.vx * 0.5 + instantVx * 0.5;
                    }
                    entity.lastX = row.x;
                    entity.lastY = row.y;
                    entity.lastTime = row.time;
                    if (row.hasHero) {
                        entity.heroId = row.heroId;
                        entity.heroName = row.heroName;
                        entity.hasHero = true;
                    }
                    if (!matched[best]) {
                        matched[best] = 1;
                        ++entity.observations;
                    }
                    row.entityIndex = best + 1;
                    row.entityObs = entity.observations;
                }

                // 缺席判定: 连续 kMissLimit 帧未观测 => 已离场
                matched.resize(entities.size(), 1);

                for (std::size_t index = 0; index < entities.size(); ++index) {
                    auto& entity = entities[index];
                    if (entity.finished) continue;

                    if (!matched[index]) {
                        ++entity.missed;
                        if (entity.missed > kMissLimit) {
                            entity.finished = true;

                            std::cout << "  [已离场] 实体#" << (index + 1)
                                << " ID=" << (entity.hasHero
                                    ? std::to_string(entity.heroId)
                                    + (entity.heroName.empty()
                                        ? "" : "(" + entity.heroName + ")") : "?")
                                << " 共观测 " << entity.observations << " 帧"
                                << std::endl;
                        }
                    }
                    else entity.missed = 0;
                }

                ++tick;

                std::size_t aliveCount = 0, goneCount = 0;
                for (const auto& entity : entities)
                    (entity.finished ? ++goneCount : ++aliveCount);

                // 每帧一行心跳, 长扫描阶段不再静默
                std::cout << "[帧" << tick << "] F 变化区域 " << f32Changed
                    << ", D 浮点 " << lastDCount
                    << ", 存活 " << aliveCount << ", 已离场 " << goneCount
                    << " (合计 " << entities.size() << ")" << std::endl;

                // 首帧校验缓存类型指针有效性 (游戏重启后模块基址变化会使缓存失效)
                if (tick == 1 && fromCache && current.size() < 20) {
                    std::cerr << "[!] 缓存类型指针疑似失效 (浮点对象过少),"
                        " 请加 --rediscover 重新识别" << std::endl;

                    delete memory;

                    return 1;
                }

                // 通道 D: PyFloatObject double (Python 逻辑值), 降频比较
                if (dTick && !previous.empty() && dt > 0.0) {
                    for (const auto& entry : current) {
                        const auto found = previous.find(entry.first);
                        if (found == previous.end()) continue;

                        const auto delta = entry.second - found->second;
                        if (delta <= -100.0 || delta >= -0.02) continue; // x 递减 = 右->左

                        auto& series = history[entry.first];
                        series.emplace_back(delta, entry.second);
                        while (series.size() > kHistoryMax) series.pop_front();

                        if (series.size() < 3) continue;

                        double deltaSum = 0.0;
                        for (const auto& sample : series) deltaSum += sample.first;

                        MoverRow row { };
                        row.channel = 'D';
                        row.x = entry.second;
                        row.address = entry.first;
                        row.vx = (deltaSum / dt) / static_cast<double>(series.size());
                        row.samples = series.size();
                        row.time = WallClockNow();

                        if (const auto hero = NearestHero(intKeys, intsAll, heroNames,entry.first)) {
                            row.hasHero = true;
                            row.heroId = *hero;
                        }
                        else {
                            // PyIntObject 邻近未命中 -> 原始 int32 局部匹配
                            bool found = false;
                            row.heroId = AttributeHeroRaw(memory, entry.first, heroNames, found);
                            row.hasHero = found;
                        }

                        if (row.hasHero) {
                            row.poolMatch = std::find(
                                options.pool.begin(), options.pool.end(), row.heroId
                            ) != options.pool.end();

                            const auto known = heroNames.find(row.heroId);
                            if (known != heroNames.end()) row.heroName = known->second;
                        }

                        rows.push_back(row);
                    }
                }

                // 实体聚类: x 相近 + y 相近的行归为同一实体
                // (同一式神的多份拷贝 / 叠放的道具), 组数即场上非道具实体数
                std::size_t ghostGroups = 0;
                {
                    std::vector<const MoverRow*> frows;
                    for (const auto& r : rows)
                        if (r.channel == 'F' && !r.item)
                            frows.push_back(&r);

                    std::sort(frows.begin(), frows.end(),
                        [](const MoverRow* left, const MoverRow* right) {
                            return left->x < right->x;
                        });

                    for (std::size_t i = 0; i < frows.size();) {
                        std::size_t j = i + 1;
                        const auto repX = frows[i]->x;
                        const auto repY = frows[i]->y;

                        while (j < frows.size()
                            && frows[j]->x - repX < 2.5
                            && std::abs(static_cast<double>(frows[j]->y) - repY) < 15.0)
                            ++j;

                        ++ghostGroups; // 一段 x/y 相近的行 = 1 只式神
                        i = j;
                    }
                }

                if (!rows.empty()) {
                    // 实体级汇总: 只列被观测 >=2 帧的实体 (一帧即逝的地址是噪声)
                    std::cout << "[" << WallClockNow() << "] 帧" << tick
                        << "  行 " << rows.size() << ", 疑似式神 " << ghostGroups
                        << ":" << std::endl;

                    std::cout << "    " << std::left << std::setw(8) << "实体"
                        << std::setw(28) << "ID·名称" << std::setw(11) << "x"
                        << std::setw(10) << "vx/秒" << std::setw(6) << "帧数"
                        << " 入场时间" << std::right << std::endl;

                    for (std::size_t index = 0; index < entities.size(); ++index) {
                        const auto& entity = entities[index];
                        if (entity.observations < 2 || entity.finished) continue;

                        std::ostringstream label { };
                        label << '#' << (index + 1);
                        if (entity.hasHero) {
                            label << ' ' << entity.heroId;
                            if (!entity.heroName.empty()) label << '·' << entity.heroName;
                        }
                        else label << " ?";

                        std::cout << "    " << std::left << std::setw(8) << label.str()
                            << std::right << std::fixed << std::setprecision(1)
                            << std::setw(11) << entity.lastX
                            << std::setw(10) << entity.vx
                            << std::setw(6) << entity.observations
                            << "  " << entity.firstTime << std::endl;
                    }

                    std::cout << std::endl;
                }

                // 行级明细只写 CSV (含 entity_obs 列, 离线可按实体过滤噪声)
                for (const auto& row : rows) {
                    if (csv) csv << row.time << ',' << row.channel
                        << ",0x" << std::hex << row.address << std::dec << ','
                        << (row.hasHero ? std::to_string(row.heroId) : "") << ','
                        << row.heroName << ','
                        << (row.poolMatch ? 1 : 0) << ','
                        << std::fixed << std::setprecision(4) << row.x << ','
                        << std::setprecision(2) << row.vx << ','
                        << row.samples << ','
                        << std::setprecision(2) << row.yRange << ','
                        << (row.item ? 1 : 0) << ','
                        << row.entityObs << '\n';
                }

                if (dTick) previous = std::move(current);

                const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - scanStart).count();

                Sleep(static_cast<DWORD>(std::max<long long>(
                    50, options.intervalMs - static_cast<long long>(elapsed))));
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

    // --gwlist: 转储疑似行走列表缓冲区 (16KB 窗口内 >=5 个不同池内 ID)
    int RunWalkList(const Options& options) {
        PMemory memory { };

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
            std::cout << "[*] 枚举区域并识别类型指针 ..." << std::endl;

            const auto qualified = CollectQualifiedRegions(memory);
            std::cout << "[*] 含百鬼标识区域: " << qualified.size() << std::endl;

            std::uintptr_t pyFloatType = 0, pyIntType = 0;
            std::size_t poolIntHits = 0;
            bool havePyInt = false;

            if (!options.rediscover && LoadTypeCache(pyFloatType, pyIntType)) {
                havePyInt = true;

                std::cout << "[*] 使用缓存类型指针: PyInt=0x" << std::hex << pyIntType
                    << std::dec << " (--rediscover 重新识别)" << std::endl;
            }
            else {
                DiscoverTypePointers(memory, qualified, options.pool,
                    false, true, pyFloatType, pyIntType, poolIntHits);

                havePyInt = pyIntType != 0;
                if (pyIntType) SaveTypeCache(pyFloatType, pyIntType);
            }

            const auto outputRoot = std::filesystem::path("yys_walklist_dump");
            std::filesystem::create_directories(outputRoot);

            std::size_t saved = 0;

            // 扫描模式: 原始 int32 数组 (行走列表的主要形式) +
            // PyIntObject ival (若类型指针已识别, 结果覆盖原始命中)
            std::uint8_t ptr8i[8] { };

            if (havePyInt) {
                std::cout << "[*] PyInt_Type=0x" << std::hex << pyIntType
                    << std::dec << std::endl;
                std::memcpy(ptr8i, &pyIntType, sizeof(ptr8i));
            }
            else {
                std::cout << "[*] 未识别 PyInt_Type (池ID出现 " << poolIntHits
                    << " 次), 仅使用原始 int32 匹配" << std::endl;
            }

            struct PendingWindow {
                std::size_t regionIndex;
                std::size_t begin;
                std::size_t end;
                std::set<std::uint64_t> ids;
            };

            std::vector<PendingWindow> pending;
            std::vector<std::map<std::size_t, std::uint64_t>> regionHitMaps(qualified.size());

            for (std::size_t regionIndex = 0; regionIndex < qualified.size(); ++regionIndex) {
                const auto& region = qualified[regionIndex];
                const auto data = ReadRegion(memory, region);

                // 收集池内 ID: 原始 int32 (4 对齐) + PyIntObject ival 覆盖
                std::map<std::size_t, std::uint64_t> hitMap { };

                for (const auto id : options.pool) {
                    std::uint8_t needle[4];
                    std::memcpy(needle, &id, sizeof(needle));

                    FindAll(data.data(), data.size(), needle, sizeof(needle),
                        [&](const std::size_t offset) {
                            if ((region.base + offset) & 3) return; // 4 对齐
                            hitMap.emplace(offset, id);
                        });
                }

                if (havePyInt) {
                    FindAll(data.data(), data.size(), ptr8i, 8,
                        [&](const std::size_t typeOffset) {
                            if (typeOffset + 12 > data.size()) return;

                            const auto value = U32At(data.data(), typeOffset + 8);
                            if (value < 100 || value > 2000) return;
                            if (std::find(options.pool.begin(), options.pool.end(),
                                static_cast<std::uint64_t>(value)) == options.pool.end()) return;

                            hitMap[typeOffset + 8] = value; // 覆盖原始命中
                        });
                }

                struct Hit { std::size_t offset; std::uint64_t value; };
                std::vector<Hit> hits;
                hits.reserve(hitMap.size());
                for (const auto& entry : hitMap) hits.push_back({ entry.first, entry.second });
                regionHitMaps[regionIndex] = std::move(hitMap);

                if (hits.size() < 6) continue;

                std::sort(hits.begin(), hits.end(),
                    [](const Hit& left, const Hit& right) { return left.offset < right.offset; });

                // 16KB 滑窗聚类, 重叠窗口合并
                struct Window { std::size_t begin; std::size_t end; std::set<std::uint64_t> ids; };
                std::vector<Window> windows { };

                constexpr std::size_t kWindow = 16 * 1024;

                for (std::size_t left = 0; left < hits.size(); ++left) {
                    std::size_t right = left;
                    while (right < hits.size()
                        && hits[right].offset - hits[left].offset < kWindow) ++right;

                    std::set<std::uint64_t> ids;
                    for (std::size_t index = left; index < right; ++index)
                        ids.insert(hits[index].value);

                    if (ids.size() >= 5) windows.push_back({ hits[left].offset,
                        hits[right - 1].offset, std::move(ids) });
                }

                std::vector<Window> merged { };
                for (auto& window : windows) {
                    if (!merged.empty() && window.begin <= merged.back().end) {
                        merged.back().end = std::max(merged.back().end, window.end);
                        merged.back().ids.insert(window.ids.begin(), window.ids.end());
                    }
                    else merged.push_back(std::move(window));
                }

                for (auto& window : merged)
                    pending.push_back({ regionIndex, window.begin, window.end,
                        std::move(window.ids) });
            }

            // 按 distinct ID 数降序, 优先转储最像"行走列表"的缓冲区
            std::sort(pending.begin(), pending.end(),
                [](const PendingWindow& left, const PendingWindow& right) {
                    return left.ids.size() > right.ids.size();
                });

            for (std::size_t order = 0;
                order < pending.size() && saved < kDumpLimit; ++order) {
                const auto& window = pending[order];
                const auto& region = qualified[window.regionIndex];
                const auto data = ReadRegion(memory, region);
                const auto& hits = regionHitMaps[window.regionIndex];

                const auto spanBegin = window.begin > 512 ? window.begin - 512 : 0;
                const auto spanEnd = std::min(data.size(), window.end + 512);

                std::ostringstream name { };
                name << "walklist_"
                    << std::setw(2) << std::setfill('0') << saved
                    << '_' << std::hex << std::setw(12) << std::setfill('0')
                    << (region.base + spanBegin) << '_' << std::setw(12)
                    << (region.base + spanEnd) << std::dec;

                const auto binPath = outputRoot / (name.str() + ".bin");
                const auto txtPath = outputRoot / (name.str() + ".txt");

                std::ofstream bin(binPath, std::ios::binary | std::ios::trunc);
                bin.write(reinterpret_cast<const char*>(data.data() + spanBegin),
                    static_cast<std::streamsize>(spanEnd - spanBegin));
                bin.close();

                std::ofstream txt(txtPath, std::ios::trunc);
                txt << "region=0x" << std::hex << region.base
                    << " span=[0x" << (region.base + spanBegin)
                    << ",0x" << (region.base + spanEnd) << "]" << std::dec
                    << " mode=raw-int32+PyIntObject"
                    << " ids=";

                for (const auto id : window.ids) txt << id << ',';

                txt << "\n\n-- 区间内式神 ID (值@绝对地址)\n";
                for (const auto& hit : hits) {
                    if (hit.first < spanBegin || hit.first >= spanEnd) continue;

                    txt << "  " << hit.second << " @ 0x"
                        << std::hex << (region.base + hit.first) << std::dec << '\n';
                }

                txt << "\n-- 区间内 float64 (地址 8 对齐, 0.05..10000)\n";
                for (std::size_t offset = spanBegin & ~static_cast<std::size_t>(7);
                    offset + 8 <= spanEnd; offset += 8) {
                    const auto value = F64At(data.data(), offset);
                    if (!std::isfinite(value) || value < 0.05 || value > 10000.0) continue;

                    txt << "  " << std::fixed << std::setprecision(4) << value
                        << " @ 0x" << std::hex << (region.base + offset) << std::dec << '\n';
                }
                txt.close();

                std::cout << "[+] 转储 " << binPath.string() << " (ID=";
                for (const auto id : window.ids) std::cout << id << ',';
                std::cout << ")" << std::endl;

                ++saved;
            }

            if (saved >= kDumpLimit) std::cout << "[*] 达到转储上限 " << kDumpLimit
                << ", 其余 " << (pending.size() - saved) << " 个窗口未转储" << std::endl;

            std::cout << "[*] 完成, 共 " << saved << " 个缓冲区 -> "
                << outputRoot.string() << std::endl;
        }
        catch (const std::exception& exception) {
            std::cerr << exception.what() << std::endl;

            delete memory;

            return 1;
        }

        delete memory;

        return 0;
    }
}
