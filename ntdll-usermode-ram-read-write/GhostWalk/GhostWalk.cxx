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
      - watch: 逐帧差分 + 位置法轨迹跟踪 (引擎每帧把坐标广播进几十份临时
        拷贝, 地址当帧失效, 按地址跟踪无效): 每帧按 x 聚类折叠镜像 ->
        跨帧预测匹配 (pred = lastX + vx*(缺席+dt)); 轨迹观测满 3 帧才写
        CSV 并补写历史行; 常数家族黑名单剔除批量写入常量; 停帧 (dt>2.5s)
        只重建快照不产出脏行; 道具/式神由轨迹级 y 范围判定;
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
#include <unordered_set>
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
            std::size_t entityObs = 0;   // 所属轨迹被观测帧数 (噪声过滤用)
            std::size_t entityIndex = 0; // 所属轨迹编号 (1 起, 0=未入轨/停帧)
            std::size_t groupRows = 0;   // 所属簇行数 (镜像折叠规模)
            double trackYRange = 0.0;    // 轨迹级 y 范围 (道具判定)
            double dtSec = 0.0;          // 本帧与上一帧真实间隔 (秒)
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
                if (csv) csv << "time,channel,addr,hero_id,hero_name,pool_match,x,"
                    "vx_units_per_s,samples,y_range,item,entity_obs,"
                    "entity_index,y,group_rows,track_y_range,dt_s\n";
            }

            // 行级 CSV 写出 (entity_index=0 表示未入轨: D 通道行或停帧帧)
            auto writeRow = [&csv](const MoverRow& row) {
                if (!csv) return;

                csv << row.time << ',' << row.channel
                    << ",0x" << std::hex << row.address << std::dec << ','
                    << (row.hasHero ? std::to_string(row.heroId) : "") << ','
                    << row.heroName << ','
                    << (row.poolMatch ? 1 : 0) << ','
                    << std::fixed << std::setprecision(4) << row.x << ','
                    << std::setprecision(2) << row.vx << ','
                    << row.samples << ','
                    << std::setprecision(2) << row.yRange << ','
                    << (row.item ? 1 : 0) << ','
                    << row.entityObs << ','
                    << row.entityIndex << ','
                    << std::setprecision(2) << row.y << ','
                    << row.groupRows << ','
                    << std::setprecision(2) << row.trackYRange << ','
                    << std::setprecision(2) << row.dtSec << '\n';
            };

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

            // 轨迹 = 跨帧连续的同一逻辑实体 (式神或道具)。
            // 行走名单由服务器下发 (bgyx_onGetWalkListAsw), 每轮数量可变, 不硬编码 36
            struct Track {
                std::size_t id = 0;
                double firstX = 0.0, lastX = 0.0, lastY = 0.0, vx = 0.0;
                double yMin = 1e30, yMax = -1e30; // 轨迹级 y 范围 (道具判定)
                std::uint64_t heroId = 0;
                std::string heroName;
                bool hasHero = false;
                std::size_t observations = 0;
                double missedTime = 0.0;   // 按真实秒数累计的缺席时长
                bool finished = false;
                bool flushed = false;      // 观测满 kFlushObs 帧后开始写 CSV
                std::vector<MoverRow> pending; // 确认前的行缓存 (确认后补写)
                std::string firstTime, lastTime;
            };

            std::vector<Track> tracks;
            std::size_t trackSeq = 0;

            // 常数家族黑名单: 同一 float32 位模式出现在多个地址且跨多帧
            // (0.0 / -489.9161 / ±1 / ±6 / 87.0 等批量写入常量)。
            // 镜像拷贝组只存活 1 帧, 达不到 "跨多帧" 判据, 不会误伤
            std::unordered_map<std::uint32_t,
                std::pair<std::unordered_set<std::uintptr_t>,
                    std::unordered_set<std::uint64_t>>> constHist;
            constexpr std::size_t kConstAddrLimit = 16;
            constexpr std::size_t kConstTickLimit = 5;

            // 位置跟踪参数
            constexpr double kClusterGap = 3.0;        // x 相邻行归簇间距
            constexpr std::size_t kClusterRowCap = 60; // 簇行数上限 (超过=噪声带)
            constexpr std::size_t kFlushObs = 3;       // 轨迹确认帧数 (持久性门槛)
            constexpr double kTrackTimeout = 12.0;     // 缺席超时 (秒, 按 dt 累计)
            constexpr double kGapFrameDt = 2.5;        // 停帧判定阈值 (秒)
            constexpr double kMatchRadius = 30.0;      // 匹配半径 (按 |vx|*时长 放大)

            while (true) {
                const auto scanStart = std::chrono::steady_clock::now();
                const auto dt = std::chrono::duration<double>(scanStart - previousScan).count();
                previousScan = scanStart;

                const bool dTick = (tick % 3 == 1) || tick <= 2;

                // 停帧判定: 真实帧间隔超阈值 (如读取阻塞 23s), 跨帧累计变化失真
                const bool gapFrame = dt > kGapFrameDt;

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
                std::size_t f32Changed = 0, f32Partial = 0, constDropped = 0;
                for (const auto& region : f32Regions) {
                    auto data = ReadRegion(memory, region);
                    if (data.size() < 8) continue;

                    // 读取不完整 (8MB 分块中途失败): 保留旧快照, 本帧跳过该区域。
                    // 旧实现把部分数据写回快照, 下一帧尺寸仍不匹配 -> 连续两帧无法差分
                    if (data.size() != region.size) {
                        ++f32Partial;
                        continue;
                    }

                    auto& prev = f32Prev[region.base];
                    if (prev.size() != data.size()) {
                        // 首帧或区域尺寸变化: 仅建立快照, 不扫描
                        prev = std::move(data);
                        continue;
                    }

                    // 停帧: 跨帧累计变化失真, 只刷新快照 (下一帧差分基线正确)
                    if (gapFrame) {
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
                        row.dtSec = dt;

                        // 屏幕坐标过滤: 剔除世界坐标/相机 (x≈9390/19262 等)
                        if (row.x < -500.0 || row.x > 2000.0) continue;

                        // 常数家族黑名单: 达标 (多地址 + 跨多帧) 后该值不再产出
                        {
                            std::uint32_t xbits { };
                            std::memcpy(&xbits, &now, sizeof(xbits));

                            auto& entry = constHist[xbits];
                            entry.first.insert(row.address);
                            entry.second.insert(tick);

                            if (entry.first.size() >= kConstAddrLimit
                                && entry.second.size() >= kConstTickLimit) {
                                ++constDropped;
                                continue;
                            }
                        }

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

                // ============ 位置法轨迹跟踪 (主跟踪器, 替代按地址的实体注册表) ============
                // 引擎每帧把坐标广播进几十份临时拷贝, 地址当帧失效, 按地址跟踪
                // 注定失败。改为: 每帧按 x 聚类折叠镜像 -> 跨帧预测匹配
                // (pred = lastX + vx*(缺席时长+dt)) -> 轨迹级维护 y 范围/速度/英雄,
                // 观测满 kFlushObs 帧才写 CSV 并补写历史行 (持久性门槛)。
                // 行走名单由服务器下发 (bgyx_onGetWalkListAsw), 每轮数量可变;
                // 每只式神速度独立 (getHeroWalkSpeed + BGYX_SPEED_FIX_MIN/MAX
                // 随机化 + FairModelSpeedFactor 全局因子), 故不硬编码总数,
                // 也不设全局统一速度门限。
                std::size_t flushedRows = 0, droppedClusterRows = 0;

                if (!gapFrame) {
                    // -- 1. F 行按 x 聚类: 链式合并间距 < kClusterGap 的行,
                    //       折叠同一式神的镜像拷贝; 行数超限的簇是锯齿噪声带, 整簇丢弃
                    struct Cluster { double cx = 0, cy = 0; std::vector<MoverRow*> rws; };
                    std::vector<Cluster> clusters;

                    {
                        std::vector<MoverRow*> frows;
                        for (auto& r : rows)
                            if (r.channel == 'F') frows.push_back(&r);

                        std::sort(frows.begin(), frows.end(),
                            [](const MoverRow* l, const MoverRow* r) {
                                return l->x < r->x;
                            });

                        for (std::size_t i = 0; i < frows.size();) {
                            std::size_t j = i + 1;
                            double sumX = frows[i]->x, sumY = frows[i]->y;

                            while (j < frows.size()
                                && frows[j]->x - frows[j - 1]->x < kClusterGap) {
                                sumX += frows[j]->x;
                                sumY += frows[j]->y;
                                ++j;
                            }

                            if (j - i > kClusterRowCap) {
                                droppedClusterRows += j - i;
                                i = j;
                                continue;
                            }

                            Cluster c;
                            c.cx = sumX / static_cast<double>(j - i);
                            c.cy = sumY / static_cast<double>(j - i);
                            c.rws.reserve(j - i);
                            for (std::size_t k = i; k < j; ++k) c.rws.push_back(frows[k]);
                            clusters.push_back(std::move(c));
                            i = j;
                        }
                    }

                    // 行归属: 轨迹确认 (kFlushObs 帧) 前缓存, 确认后补写历史行
                    auto attach = [&](Track& tr, Cluster& c) {
                        if (tr.observations >= 1) {
                            const auto instantVx =
                                (c.cx - tr.lastX) / (tr.missedTime + dt);
                            tr.vx = tr.vx * 0.5 + instantVx * 0.5;
                        }

                        tr.lastX = c.cx;
                        tr.lastY = c.cy;
                        tr.lastTime = c.rws.front()->time;
                        ++tr.observations;
                        tr.missedTime = 0;

                        for (const auto* r : c.rws) {
                            tr.yMin = std::min(tr.yMin, static_cast<double>(r->y));
                            tr.yMax = std::max(tr.yMax, static_cast<double>(r->y));

                            if (!tr.hasHero && r->hasHero) {
                                tr.hasHero = true;
                                tr.heroId = r->heroId;
                                tr.heroName = r->heroName;
                            }
                        }

                        const bool itemTrack = (tr.yMax - tr.yMin) > options.yVar;

                        for (auto* r : c.rws) {
                            r->entityIndex = tr.id;
                            r->entityObs = tr.observations;
                            r->groupRows = c.rws.size();
                            r->trackYRange = tr.yMax - tr.yMin;
                            r->item = itemTrack;
                        }

                        if (tr.flushed) {
                            for (const auto* r : c.rws) {
                                writeRow(*r);
                                ++flushedRows;
                            }
                        }
                        else {
                            for (const auto* r : c.rws) tr.pending.push_back(*r);

                            if (tr.observations >= kFlushObs) {
                                for (const auto& r : tr.pending) {
                                    writeRow(r);
                                    ++flushedRows;
                                }

                                tr.pending.clear();
                                tr.pending.shrink_to_fit();
                                tr.flushed = true;
                            }
                        }
                    };

                    // -- 2. 簇 -> 已有轨迹: 预测位置贪心匹配 (只接受向左运动) --
                    struct Cand { std::size_t ti, ci; double d; };
                    std::vector<Cand> cands;

                    for (std::size_t ti = 0; ti < tracks.size(); ++ti) {
                        const auto& tr = tracks[ti];
                        if (tr.finished) continue;

                        const auto pred = tr.lastX
                            + (tr.observations > 1
                                ? tr.vx * (tr.missedTime + dt) : 0.0);
                        const auto radius = std::max(kMatchRadius,
                            std::abs(tr.vx) * (tr.missedTime + dt) * 1.5 + 8.0);

                        for (std::size_t ci = 0; ci < clusters.size(); ++ci) {
                            if (clusters[ci].cx > pred + 6.0) continue; // 右移=噪声

                            const auto d = std::abs(clusters[ci].cx - pred);
                            if (d < radius) cands.push_back({ ti, ci, d });
                        }
                    }

                    std::sort(cands.begin(), cands.end(),
                        [](const Cand& l, const Cand& r) { return l.d < r.d; });

                    std::vector<char> trackUsed(tracks.size(), 0);
                    std::vector<char> cluUsed(clusters.size(), 0);

                    for (const auto& c : cands) {
                        if (trackUsed[c.ti] || cluUsed[c.ci]) continue;

                        trackUsed[c.ti] = 1;
                        cluUsed[c.ci] = 1;
                        attach(tracks[c.ti], clusters[c.ci]);
                    }

                    // -- 3. 未匹配簇 -> 新轨迹 --
                    for (std::size_t ci = 0; ci < clusters.size(); ++ci) {
                        if (cluUsed[ci]) continue;

                        Track tr;
                        tr.id = ++trackSeq;
                        tr.lastX = tr.firstX = clusters[ci].cx;
                        tr.lastY = clusters[ci].cy;
                        tr.vx = clusters[ci].rws.front()->vx;
                        tr.firstTime = tr.lastTime = clusters[ci].rws.front()->time;

                        tracks.push_back(std::move(tr));
                        attach(tracks.back(), clusters[ci]);
                    }

                    // 本帧新入场的轨迹: 扩容 trackUsed 并记为已观测 (1)。
                    // 否则步骤 4 的 trackUsed[ti] 越界 -> vector subscript out of range
                    trackUsed.resize(tracks.size(), 1);

                    // -- 4. 未匹配轨迹: 按真实秒数累计缺席, 超时判离场 --
                    for (std::size_t ti = 0; ti < tracks.size(); ++ti) {
                        auto& tr = tracks[ti];
                        if (tr.finished || trackUsed[ti]) continue;

                        tr.missedTime += dt;

                        if (tr.missedTime > kTrackTimeout) {
                            tr.finished = true;

                            // 未确认 (观测 < kFlushObs) 的轨迹视为噪声, 静默丢弃
                            if (tr.observations >= kFlushObs) {
                                std::cout << "  [离场] 轨迹#" << tr.id
                                    << (tr.hasHero
                                        ? " " + std::to_string(tr.heroId)
                                            + (tr.heroName.empty()
                                                ? "" : "·" + tr.heroName)
                                        : "")
                                    << " 共观测 " << tr.observations << " 帧"
                                    << std::fixed << std::setprecision(1)
                                    << " x " << tr.firstX << "->" << tr.lastX
                                    << " yRange " << (tr.yMax - tr.yMin)
                                    << ((tr.yMax - tr.yMin) > options.yVar
                                        ? " [道具]" : "")
                                    << " (" << tr.firstTime << " -> "
                                    << tr.lastTime << ")" << std::endl;
                            }
                        }
                    }
                }

                ++tick;

                std::size_t aliveCount = 0, goneCount = 0;
                for (const auto& tr : tracks)
                    (tr.finished ? ++goneCount : ++aliveCount);

                // 每帧一行心跳, 长扫描阶段不再静默
                std::cout << "[帧" << tick << "] F 变化区域 " << f32Changed
                    << (f32Partial
                        ? " (部分读失败区域 " + std::to_string(f32Partial) + ")"
                        : std::string())
                    << ", D 浮点 " << lastDCount
                    << ", 轨迹 存活 " << aliveCount << " 离场 " << goneCount
                    << " (累计 " << tracks.size() << ")" << std::endl;

                // 首帧校验缓存类型指针有效性 (游戏重启后模块基址变化会使缓存失效)
                if (tick == 1 && fromCache && current.size() < 20) {
                    std::cerr << "[!] 缓存类型指针疑似失效 (浮点对象过少),"
                        " 请加 --rediscover 重新识别" << std::endl;

                    delete memory;

                    return 1;
                }

                // 通道 D: PyFloatObject double (Python 逻辑值), 降频比较
                // (Python float 每次赋值都是新对象, 地址必然翻腾, 此通道仅作参考)
                if (dTick && !previous.empty() && dt > 0.0 && !gapFrame) {
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
                        row.dtSec = dt;

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

                        writeRow(row);
                    }
                }

                // 帧摘要: 行数/黑名单与噪声簇丢弃/写出行数 + 存活轨迹表
                // (F 行已在轨迹确认后写盘, 此处不再整批写 CSV)
                std::cout << "[" << WallClockNow() << "] 帧" << tick
                    << " dt=" << std::fixed << std::setprecision(2) << dt << "s"
                    << " 行 " << rows.size()
                    << " (常数黑名单-" << constDropped
                    << " 噪声簇-" << droppedClusterRows
                    << " 写出 " << flushedRows << ")"
                    << " | 轨迹 存活 " << aliveCount
                    << " 离场 " << goneCount
                    << " 累计 " << tracks.size()
                    << std::endl;

                if (!gapFrame) {
                    for (const auto& tr : tracks) {
                        if (tr.finished || tr.observations < 2) continue;

                        std::ostringstream label { };
                        label << '#' << tr.id;
                        if (tr.hasHero) {
                            label << ' ' << tr.heroId;
                            if (!tr.heroName.empty()) label << '·' << tr.heroName;
                        }
                        else label << " ?";

                        std::cout << "    " << std::left << std::setw(10) << label.str()
                            << std::right << std::fixed << std::setprecision(1)
                            << " x=" << std::setw(8) << tr.lastX
                            << " vx=" << std::setprecision(2) << std::setw(7) << tr.vx
                            << " obs=" << tr.observations
                            << " yRange=" << std::setprecision(1)
                            << (tr.yMax - tr.yMin)
                            << ((tr.yMax - tr.yMin) > options.yVar ? " [道具]" : "")
                            << "  " << tr.firstTime << std::endl;
                    }

                    std::cout << std::endl;
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
