#pragma once

#include <iostream>
#include <format>
#include <string>

#define CONSOLE_FMT_PRINT(msg, ...) CONSOLE_PRINT(std::format(msg, __VA_ARGS__))
#define CONSOLE_PRINT(msg) std::cout << msg
#define NAME_FROM_PATH(path) path.substr(path.find_last_of("/\\") + 1)