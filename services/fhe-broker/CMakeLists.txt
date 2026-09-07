# CV-ZTTE native FHE broker (spec §36). Links against the pinned OpenFHE 1.5.1
# install (see env.sh: CVZTTE_OPENFHE_HOME). Build:
#   cmake -S services/fhe-broker -B services/fhe-broker/build \
#         -DOpenFHE_DIR=$CVZTTE_OPENFHE_HOME/lib/OpenFHE
#   cmake --build services/fhe-broker/build
cmake_minimum_required(VERSION 3.16)
project(cvztte_fhe_broker CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenFHE REQUIRED)

add_executable(fhe_broker src/fhe_broker.cpp)

target_include_directories(fhe_broker PRIVATE
    ${OpenFHE_INCLUDE}
    ${OpenFHE_INCLUDE}/core
    ${OpenFHE_INCLUDE}/pke
    ${OpenFHE_INCLUDE}/binfhe)

# OpenFHE ships its own required compile flags (MATHBACKEND, OpenMP, etc.).
separate_arguments(OPENFHE_CXX_FLAGS_LIST UNIX_COMMAND "${OpenFHE_CXX_FLAGS}")
target_compile_options(fhe_broker PRIVATE ${OPENFHE_CXX_FLAGS_LIST})

target_link_directories(fhe_broker PRIVATE ${OpenFHE_LIBDIR})
target_link_libraries(fhe_broker PRIVATE ${OpenFHE_SHARED_LIBRARIES})
set_target_properties(fhe_broker PROPERTIES
    BUILD_RPATH "${OpenFHE_LIBDIR}"
    INSTALL_RPATH "${OpenFHE_LIBDIR}")
