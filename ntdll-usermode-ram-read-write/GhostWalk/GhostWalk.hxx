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
    };

    // --ghostwalk: 差分追踪右->左移动的坐标对象 (PyFloatObject) 并归属式神 ID
    int RunWatch(const Options& options);

    // --gwlist: 转储同时含 >=5 个池内 ID 的缓冲区 (服务器下发的行走列表)
    int RunWalkList(const Options& options);
}

#endif /* !GHOSTWALK_HXX */
