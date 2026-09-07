cmake_minimum_required(VERSION 3.16)
project(cvztte_openfhe_smoke CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# OpenFHE_DIR points at the installed lib/OpenFHE with OpenFHEConfig.cmake.
find_package(OpenFHE REQUIRED)

add_executable(smoke_openfhe smoke_openfhe.cpp)

target_include_directories(smoke_openfhe PRIVATE
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe)

target_link_libraries(smoke_openfhe PRIVATE
    OPENFHEpke OPENFHEcore OPENFHEbinfhe)
