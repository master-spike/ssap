cmake_minimum_required(VERSION 3.20)

project(ssap)

find_package(Catch2 3 REQUIRED)
find_package(OpenSSL REQUIRED)

set(SSAP_OBJS
    participant)

add_library(ssap "lib/${SSAP_OBJS}.cpp")
target_include_directories(ssap PUBLIC include/ssap)
target_include_directories(ssap PRIVATE lib)

set_property(TARGET ssap PROPERTY CXX_STANDARD 20)

set(SSAP_TESTS
    crypto/keymanager_test)

include(CTest)
include(Catch)

foreach(test IN LISTS SSAP_TESTS)
    cmake_path(GET test PARENT_PATH exe_path)
    cmake_path(GET test FILENAME exe_name)
    add_executable(${exe_name} "test/${test}.cpp")
    set_target_properties(${exe_name} PROPERTIES RUNTIME_OUTPUT_DIRECTORY 
        "test/${exe_path}")
    target_link_libraries(${exe_name} PRIVATE ssap Catch2::Catch2WithMain crypto)
    target_include_directories(${exe_name} PRIVATE lib)
    set_property(TARGET ${exe_name} PROPERTY CXX_STANDARD 20)
    catch_discover_tests(${exe_name})
endforeach()
