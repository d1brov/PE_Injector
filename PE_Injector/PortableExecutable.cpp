#include "PortableExecutable.h"
#include "PeInjectorException.h"

#include <fstream>

PortableExecutable::PortableExecutable(const std::string& pe_path)
    : file_path_(pe_path)
    , file_name_(NAME_FROM_PATH(pe_path)) {

    // Load executable
    std::ifstream instream(file_path_, std::ios::in | std::ios::binary);
    if (!instream.is_open()) {
        throw std::runtime_error(std::format(
            "Cant open [{}] for reading", NAME_FROM_PATH(file_path_)));
    }
    bytes_ = std::vector<uint8_t>((std::istreambuf_iterator<char>(instream)), std::istreambuf_iterator<char>());
    instream.close();
    if (bytes_.size() == 0) {
        throw PeInjectorException("Executable file is empty");
    }

    // Parse & verify DOS header
    dos_header_ = (PIMAGE_DOS_HEADER)&bytes_[0];
    if (dos_header_->e_magic != 0x5A4D) {
        throw std::runtime_error("Invalid DOS header");
    }

    auto headers_ptr = (uint8_t*)(&bytes_[dos_header_->e_lfanew]);

    // Parse & verify executable signature
    auto signature = (DWORD*)(&bytes_[dos_header_->e_lfanew]);
    if (*signature != IMAGE_NT_SIGNATURE) {
        throw std::runtime_error("Invalid header signature");
    }

    // Parse file header
    auto file_header = (PIMAGE_FILE_HEADER)(headers_ptr + sizeof(DWORD));

    // Parse pointer to Nt Headers
    auto opt_header_ptr = (uint8_t*)file_header + sizeof(IMAGE_FILE_HEADER);

    // Parse corresponding optional header (32/64 bit)
    executable_type_ = file_header->Machine;
    switch (executable_type_) {
    case IMAGE_FILE_MACHINE_AMD64: {
        headers64_ = (PIMAGE_NT_HEADERS64)headers_ptr;
        auto opt_header64 = (PIMAGE_OPTIONAL_HEADER64)opt_header_ptr;
        file_alignment_ = opt_header64->FileAlignment;
        data_directory_ = opt_header64->DataDirectory;
        section_directory_ = (PIMAGE_SECTION_HEADER)(opt_header_ptr + sizeof(IMAGE_OPTIONAL_HEADER64));
        break;
    }

    case IMAGE_FILE_MACHINE_I386: {
        headers32_ = (PIMAGE_NT_HEADERS32)headers_ptr;
        auto opt_header32 = (IMAGE_OPTIONAL_HEADER32*)opt_header_ptr;
        file_alignment_ = opt_header32->FileAlignment;
        data_directory_ = opt_header32->DataDirectory;
        section_directory_ = (PIMAGE_SECTION_HEADER)(opt_header_ptr + sizeof(IMAGE_OPTIONAL_HEADER32));
        break;
    }

    default:
        throw std::runtime_error("Unsuported executable\n");
    }

    // Get data directory if executable has it
    if (data_directory_[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0) {
        auto import_table_rva =
            data_directory_[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;

        if (import_table_rva == NULL) {
            throw std::runtime_error("Invalid header signature");
        }
        import_table_ = (PIMAGE_IMPORT_DESCRIPTOR)ConvertRva(import_table_rva);
    }

}

uint8_t* PortableExecutable::ConvertRva(const uint32_t rva) {
    uint8_t* address{ nullptr };
    for (WORD section_index{}; section_index < headers32_->FileHeader.NumberOfSections; section_index++) {
        auto section = section_directory_ + section_index;
        auto section_end = section->VirtualAddress + section->SizeOfRawData;

        if (section->VirtualAddress <= rva && rva < section_end) {
            address = &bytes_[section->PointerToRawData];
            address += (rva - section->VirtualAddress);
            return address;
        }
    }
    return address;
}

void PortableExecutable::PrintImportTable() {
    switch (executable_type_) {
    case IMAGE_FILE_MACHINE_AMD64: {
        PrintImportTable<IMAGE_THUNK_DATA64>();
        break;
    }

    case IMAGE_FILE_MACHINE_I386: {
        PrintImportTable<IMAGE_THUNK_DATA32>();
        break;
    }
    }
}

template<typename ThunkType>
void PortableExecutable::PrintImportTable() {
    auto ordinal_flag = (executable_type_ == IMAGE_FILE_MACHINE_AMD64) ? IMAGE_ORDINAL_FLAG64 : IMAGE_ORDINAL_FLAG32;
    for (auto header{ import_table_ }; header->Name != 0; header++) {
        CONSOLE_FMT_PRINT("{}\n", (char*)ConvertRva(header->Name));
        auto thunk = header->OriginalFirstThunk ? header->OriginalFirstThunk : header->FirstThunk;
        auto thunk_data = (ThunkType*)ConvertRva(thunk);
        for (; thunk_data->u1.AddressOfData != 0; thunk_data++) {
            if (thunk_data->u1.AddressOfData & ordinal_flag) {
                CONSOLE_FMT_PRINT(" - ORDINAL:{:#08x}\n", thunk_data->u1.AddressOfData);
            }
            else {
                CONSOLE_FMT_PRINT(" - {}\n", (char*)ConvertRva(thunk_data->u1.AddressOfData + 2)); // Why +2 ?
            }
        }
        CONSOLE_PRINT("\n");
    }
}

void PortableExecutable::AddDllToImportTable(const std::string& dll_path) {
    std::string dll_name = NAME_FROM_PATH(dll_path);

    auto sections_offset = dos_header_->e_lfanew
        + sizeof(DWORD)
        + sizeof(IMAGE_FILE_HEADER)
        + headers32_->FileHeader.SizeOfOptionalHeader;

    auto last_section = (PIMAGE_SECTION_HEADER)&bytes_[
        sections_offset
            + (headers32_->FileHeader.NumberOfSections - 1) * sizeof(IMAGE_SECTION_HEADER)
    ];

    auto new_section_va = last_section->VirtualAddress + last_section->SizeOfRawData;
    auto new_data_pos = last_section->PointerToRawData + last_section->SizeOfRawData;

    // Calculate number of imported modules
    DWORD module_number = 0;
    for (auto import_header{ import_table_ }; import_header->Name != 0; import_header++) {
        module_number++;
    }

    /*
        [0] - imported dll descriprtor
        [1] - last descriptor in chain must be empty
    */
    IMAGE_IMPORT_DESCRIPTOR imported_dll_descriptors[2] = { 0 };

    // Init lookup table entries
    IMAGE_THUNK_DATA64 ImportLookupTable64[2] = {};
    ImportLookupTable64[0].u1.Ordinal = 0x8000000000000001;
    IMAGE_THUNK_DATA32 ImportLookupTable32[2] = {};
    ImportLookupTable32[0].u1.Ordinal = 0x80000001;

    // Calculate size of new import table
    DWORD orig_import_table_size = module_number * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    DWORD new_import_table_size = orig_import_table_size + sizeof(imported_dll_descriptors);

    // Set imported dll descryptor parameters
    imported_dll_descriptors[0].Name = new_section_va + new_import_table_size;
    imported_dll_descriptors[0].OriginalFirstThunk = (DWORD)(imported_dll_descriptors[0].Name + dll_name.size() + 1);
    imported_dll_descriptors[0].FirstThunk = imported_dll_descriptors[0].OriginalFirstThunk;
    imported_dll_descriptors[0].FirstThunk +=
        (executable_type_ == IMAGE_FILE_MACHINE_AMD64) ? sizeof(ImportLookupTable64) : sizeof(ImportLookupTable32);

    // Update IAT directory
    data_directory_[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = new_section_va;
    data_directory_[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = new_import_table_size;

    // calculate total length of additional data to append
    auto added_bytes_count = new_import_table_size;
    added_bytes_count += (DWORD)dll_name.size() + 1;

    added_bytes_count += (executable_type_ == IMAGE_FILE_MACHINE_AMD64) ?
        sizeof(ImportLookupTable64) : sizeof(ImportLookupTable32);

    // calculate number of uint8_ts to pad (section data in file must be aligned)
    auto padding_bytes = file_alignment_ - (added_bytes_count % file_alignment_);
    if (padding_bytes == file_alignment_) {
        padding_bytes = 0;
    }
    added_bytes_count += padding_bytes;

    // Set last section's read/write permissions to allow the loader to store the resolved IAT value
    last_section->Characteristics |= IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;
    last_section->SizeOfRawData += added_bytes_count;
    last_section->Misc.VirtualSize += added_bytes_count;

    uint8_t* lookup_table{};
    size_t lookup_table_size{};
    switch (executable_type_) {
    case IMAGE_FILE_MACHINE_AMD64: {
        headers64_->OptionalHeader.SizeOfImage += added_bytes_count;
        lookup_table = (uint8_t*)&ImportLookupTable64[0];
        lookup_table_size = sizeof(ImportLookupTable64);

        break;
    }

    case IMAGE_FILE_MACHINE_I386: {
        headers32_->OptionalHeader.SizeOfImage += added_bytes_count;
        lookup_table = (uint8_t*)&ImportLookupTable32[0];
        lookup_table_size = sizeof(ImportLookupTable32);
        break;
    }
    }

    // check if debug symbols are currently stored at the end of the exe
    if (headers32_->FileHeader.PointerToSymbolTable == new_data_pos) {
        // adjust debug symbol ptr
        headers32_->FileHeader.PointerToSymbolTable += added_bytes_count;
    }

    // Open original executable file for rewrite
    std::string patched_pe_path = file_path_;
    patched_pe_path.append("_patched.exe");
    std::ofstream outstream(patched_pe_path, std::ios::binary | std::ios::trunc);
    if (!outstream.is_open()) {
        throw std::runtime_error(std::format(
            "Cant open [{}] for writing", file_name_));
    }

    // Append original executable headers
    outstream.write((char*)&bytes_[0], new_data_pos);

    ///// Appdend original import table
    outstream.write((char*)import_table_, orig_import_table_size);
    // Append new import table descriptors
    outstream.write((char*)imported_dll_descriptors, sizeof(imported_dll_descriptors));

    // Appdend dll name
    outstream.write(dll_name.c_str(), dll_name.size() + 1);

    // Append lookup table
    outstream.write((char*)lookup_table, lookup_table_size);
    outstream.write((char*)lookup_table, lookup_table_size);

    // Append EOF padding
    std::vector<char> padding(padding_bytes);
    outstream.write(&padding[0], padding.size());

    for (size_t i{}; i < padding_bytes; i++) {
        outstream << (uint8_t)0;
    }
}