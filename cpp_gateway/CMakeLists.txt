cmake_minimum_required(VERSION 3.14)
project(vix_cpp_gateway CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(USE_QUICHE "Build with quiche (QUIC + H3)" ON)
option(USE_PROTOBUF "Enable Protocol Buffers responses" ON)

if (USE_QUICHE)
    if (NOT DEFINED QUICHE_INCLUDE_DIR)
        message(FATAL_ERROR "QUICHE_INCLUDE_DIR not set. Pass -DQUICHE_INCLUDE_DIR=/path/to/quiche/include")
    endif()
    if (NOT DEFINED QUICHE_LIB)
        message(FATAL_ERROR "QUICHE_LIB not set. Pass -DQUICHE_LIB=/path/to/libquiche.a")
    endif()
    include_directories(${QUICHE_INCLUDE_DIR})
endif()

set(GATEWAY_SOURCES src/main.cpp)

if (USE_PROTOBUF)
    find_package(Protobuf REQUIRED)
    include_directories(${Protobuf_INCLUDE_DIRS})
    # Generate C++ from proto
    set(VIX_FS_PROTO ${CMAKE_CURRENT_LIST_DIR}/../proto/fs.proto)
    protobuf_generate_cpp(FS_PROTO_SRCS FS_PROTO_HDRS ${VIX_FS_PROTO})
    list(APPEND GATEWAY_SOURCES ${FS_PROTO_SRCS})
endif()

add_executable(vix_cpp_gateway ${GATEWAY_SOURCES})

if (USE_QUICHE)
    target_compile_definitions(vix_cpp_gateway PRIVATE QUICHE_AVAILABLE=1)
    target_link_libraries(vix_cpp_gateway PRIVATE ${QUICHE_LIB})
endif()

# Link common system libs often needed with quiche (OpenSSL, crypto)
if (DEFINED QUICHE_EXTRA_LIBS)
    # Split semicolon-separated list
    separate_arguments(QUICHE_EXTRA_LIBS)
    target_link_libraries(vix_cpp_gateway PRIVATE ${QUICHE_EXTRA_LIBS})
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(vix_cpp_gateway PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()

if (USE_PROTOBUF)
    target_compile_definitions(vix_cpp_gateway PRIVATE PROTOBUF_AVAILABLE=1)
    target_include_directories(vix_cpp_gateway PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(vix_cpp_gateway PRIVATE ${Protobuf_LIBRARIES})
endif()

if (APPLE)
    # poll/select are fine; no extra flags
elseif(UNIX)
    target_link_libraries(vix_cpp_gateway PRIVATE pthread dl)
endif()

# ---- Packaging & Installation ----
include(InstallRequiredSystemLibraries)

# Install the binary
install(TARGETS vix_cpp_gateway DESTINATION bin)

# Optionally install an extra shared library (e.g., a Rust .so) if provided
# Pass -DVIX_EXTRA_SHARED_LIB=/absolute/path/to/libsomething.so to enable
if (DEFINED VIX_EXTRA_SHARED_LIB AND EXISTS ${VIX_EXTRA_SHARED_LIB})
  install(FILES ${VIX_EXTRA_SHARED_LIB} DESTINATION lib)
endif()

set(CPACK_PACKAGE_NAME "vix-cpp-gateway")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_GENERATOR "DEB;RPM")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Vistrix Labs <info@vistrix.in>")
include(CPack)
