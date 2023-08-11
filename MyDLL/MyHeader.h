#pragma once

#ifdef MY_HEADER_EXPORTS
#define MY_HEADER_API __declspec(dllexport)
#else
#define MY_HEADER_API __declspec(dllimport)
#endif

extern "C" MY_HEADER_API void Speak();
