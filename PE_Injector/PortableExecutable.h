#pragma once
#include "Printer.h"

#include <stdio.h>
#include <vector>
#include <Windows.h>

class PortableExecutable {
public:
    PortableExecutable() = delete;
    explicit PortableExecutable(const std::string& pe_path);
    uint8_t* ConvertRva(const uint32_t rva);
    void PrintImportTable();
    void AddDllToImportTable(const std::string& dll_path);

private:
    template <typename ThunkType>
    void PrintImportTable();

    std::string file_name_{};
    std::string file_path_{};
    std::vector<uint8_t> bytes_{};

    WORD executable_type_{};
    PIMAGE_DOS_HEADER dos_header_{};
    union {
        IMAGE_NT_HEADERS32* headers32_;
        IMAGE_NT_HEADERS64* headers64_;
    };

    PIMAGE_DATA_DIRECTORY data_directory_{};
    DWORD file_alignment_{};
    PIMAGE_SECTION_HEADER section_directory_{};
    IMAGE_IMPORT_DESCRIPTOR* import_table_{};
};
