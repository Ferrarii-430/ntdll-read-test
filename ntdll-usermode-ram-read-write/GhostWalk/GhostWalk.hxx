/*
    File GhostWalk.hxx
    百鬼夜行 (GhostWalk / BaiGuiYeXing) 运行时只读探针
    -- yys_ghostwalk_reader.py 的 C++/ntdll 移植
*/

#ifndef GHOSTWALK_HXX
#define GHOSTWALK_HXX

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace GhostWalk {
    struct Options {
        int intervalMs = 800;              // watch 模式逐帧间隔
        std::vector<std::uint64_t> pool;   // 式神 ID 池 (高亮/聚类), 默认 baigui_hero_full
        std::string csvPath;               // watch 模式 CSV 输出路径, 可空
        bool rediscover = false;           // 忽略类型指针缓存, 强制重新识别
        double yVar = 3.0;                 // Y 轴变化幅度阈值: 超过视为道具(上下移动)
        std::string namesPath = "shishen.json"; // 官方式神 ID->名称表路径
        bool freezeOnHit = false;          // gwwatch: 命中列表时冻结进程再转储
    };

    // --ghostwalk: 差分追踪右->左移动的坐标对象 (PyFloatObject) 并归属式神 ID
    int RunWatch(const Options& options);

    // --gwlist: 转储同时含 >=5 个池内 ID 的缓冲区 (服务器下发的行走列表)
    int RunWalkList(const Options& options);

    // --gwstate: 指针追踪转储 (锚定 lsw/walkList 等, 级联转储引用区域)
    int RunStateChase(const Options& options);

    // --gwparse: 启发式定位 lsw (36 元素 dict list) 并逐 dict 解析键名与值
    int RunGwParse(const Options& options);

    // --gwfind: 定向查找 lsw/walkList/ls 等键名 str 对象, 反查 dict entries
    // 中 me_key 指向它们的槽位, 直接转储值容器 (list/tuple/dict/None)
    int RunGwFind(const Options& options);

    // --gwwatch: 锁定 lsw/walkList 的值槽位后低频轮询, 列表 size>=30 时
    // 自动转储全部元素 (解决 lsw 仅回合内存活的时机问题)
    int RunGwWatch(const Options& options);

    // --gwtype: 按类名定位 heap type 对象 -> 扫描类实例 -> 转储实例 __dict__
    // (直接拿成员对象的字段名, 不依赖 lsw 容器)
    int RunGwType(const Options& options);
}

#endif /* !GHOSTWALK_HXX */
