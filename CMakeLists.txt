cmake_minimum_required(VERSION 3.10.2)
project(AFIT-CSCE689-HW4-S)

set(CMAKE_CXX_STANDARD 14)

add_executable(AFIT-CSCE689-HW4 src/repsvr_main.cpp
        src/TCPServer.cpp       include/TCPServer.h
        src/TCPConn.cpp         include/TCPConn.h
        src/strfuncts.cpp       include/strfuncts.h
        src/Server.cpp          include/Server.h
        src/ReplServer.cpp      include/ReplServer.h
        src/QueueMgr.cpp        include/QueueMgr.h
        src/LogMgr.cpp          include/LogMgr.h
        src/FileDesc.cpp        include/FileDesc.h
        src/DronePlotDB.cpp     include/DronePlotDB.h
        src/AntennaSim.cpp      include/AntennaSim.h
        src/ALMgr.cpp           include/ALMgr.h
                                include/exceptions.h
        )
add_executable(testStuff
        test.cpp)

target_include_directories(AFIT-CSCE689-HW4 PRIVATE src include)
INCLUDE(FindPkgConfig)
pkg_search_module(CRYPTOPP REQUIRED libcrypto++ >= 6)

target_link_libraries(AFIT-CSCE689-HW4 pthread ${CRYPTOPP_LIBRARIES})


