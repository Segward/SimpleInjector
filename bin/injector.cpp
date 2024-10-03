#include "routine.hpp"

int main(const int argc, const char* argv[]) {
    
    if (argc < 2) {
        std::cerr << "Missing Arguments: <process name> <dll path>" << std::endl;
        return 1;
    }

    if (argc == 2 && strcmp(argv[1], "--help") == 0) {
        std::cerr << "Basic Usage: injector <process name> <dll path>" << std::endl;
        return 1;
    }

    const char* processName = argv[1];
    const char* dllPath = argv[2];

    Routine routine(processName, dllPath);
    if (routine.CreateRemoteThreadInject()) {
        std::cout << "Injection successful" << std::endl;
    } else {
        std::cerr << "Injection failed" << std::endl;
    }

    return 0;
}