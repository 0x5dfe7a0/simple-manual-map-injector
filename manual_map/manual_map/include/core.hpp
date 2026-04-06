#pragma once

#include <windows.h>
#include <winternl.h>
#include <fstream>
#include <thread>
#include <chrono>
#include <string>
#include <vector>

#pragma comment( lib , "ntdll.lib" )

#include <include/manual_map/manual_map.hpp>
inline auto g_manual_map = std::make_shared<c_manual_map >( );