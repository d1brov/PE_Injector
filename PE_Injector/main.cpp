#include "Printer.h"
#include "PortableExecutable.h"

int main(int argc, char* argv[]) {

    if (argc < 2 || argc > 3) {
        CONSOLE_PRINT("Invalid argument count.\n\n");
        auto this_name = NAME_FROM_PATH(std::string(argv[0]));
        CONSOLE_FMT_PRINT("Usage: {} pe_path [dll_path]\n", this_name);
        CONSOLE_PRINT("Parameters:\n");
        CONSOLE_PRINT("\tpe_path - path to executable.\n");
        CONSOLE_PRINT("\tdll_path - path to DLL to be imported into PE.\n");
        return 0;
    }

	try {
        std::string pe_path = argv[1];
        PortableExecutable executable(pe_path);

        if (argc == 2) {
            executable.PrintImportTable();
        }

		if (argc == 3) {
			std::string dll_name = NAME_FROM_PATH(std::string(argv[2]));
			if (dll_name.ends_with(".dll") || dll_name.ends_with(".DLL")) {
                executable.AddDllToImportTable(dll_name);
                CONSOLE_PRINT("Patched succesfully\n");
				return 0;
            }
            else {
				CONSOLE_PRINT("Invalid .dll format\n");
                return 1;
            }
		}
	}
	catch (const std::exception& e) {
        CONSOLE_FMT_PRINT("{}\n", e.what());
        return 1;
	}
}