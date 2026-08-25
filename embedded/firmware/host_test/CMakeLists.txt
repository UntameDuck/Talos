# Host-side unit tests for BoundKey pure-C modules (지시서 §22).
# ESP-IDF 불필요. gcc/clang + cmake 로 빌드.
cmake_minimum_required(VERSION 3.16)
project(boundkey_host_tests C)
set(CMAKE_C_STANDARD 11)
enable_testing()

add_executable(test_policy test_policy.c ../security/policy.c)
target_include_directories(test_policy PRIVATE ../security)
add_test(NAME policy COMMAND test_policy)

add_executable(test_approval test_approval.c ../approval/approval.c)
target_include_directories(test_approval PRIVATE ../approval)
add_test(NAME approval COMMAND test_approval)
