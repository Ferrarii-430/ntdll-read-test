cmake_minimum_required(VERSION 3.20)

project(ntdll-usermode-ram-read-write CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 默认输出到 Build/ 目录（与原 vcxproj 保持一致）
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/Build)

if(MSVC)
    # 源文件含中文注释，按 UTF-8 处理避免 C4819 警告
    add_compile_options(/utf-8 /W3)
else()
    add_compile_options(-Wall -Wextra -Wno-redundant-decls)
endif()

add_executable(${PROJECT_NAME}
        ntdll-usermode-ram-read-write/Main.cxx
        ntdll-usermode-ram-read-write/Memory/Memory.cxx
        ntdll-usermode-ram-read-write/GhostWalk/GhostWalk.cxx
)

target_include_directories(${PROJECT_NAME} PRIVATE ntdll-usermode-ram-read-write)