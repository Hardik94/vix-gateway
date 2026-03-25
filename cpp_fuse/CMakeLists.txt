cmake_minimum_required(VERSION 3.12)
project(vix_cpp_fuse CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(FUSE3 REQUIRED fuse3)
find_package(Threads REQUIRED)

set(SRC_FILES
  src/main.cpp
  src/transport.h
)

set(LINK_LIBS ${FUSE3_LIBRARIES})

# Accept legacy alias USE_PROTO and map it to USE_PROTOBUF if provided
if (DEFINED USE_PROTO AND NOT DEFINED USE_PROTOBUF)
  set(USE_PROTOBUF ${USE_PROTO})
  message(STATUS "Aliasing USE_PROTO -> USE_PROTOBUF = ${USE_PROTOBUF}")
endif()

option(USE_PROTOBUF "Enable Protocol Buffers for metadata" OFF)
if (USE_PROTOBUF)
  find_package(Protobuf REQUIRED)
  include_directories(${Protobuf_INCLUDE_DIRS})
  set(PROTO_FILE "../proto/fs.proto")
  if (EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${PROTO_FILE})
    protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILE})
    list(APPEND SRC_FILES ${PROTO_SRCS} ${PROTO_HDRS})
  else()
    message(WARNING "Proto file not found: ${PROTO_FILE}. Ensure codegen provided.")
  endif()
  list(APPEND LINK_LIBS ${Protobuf_LIBRARIES})
  add_definitions(-DUSE_PROTOBUF)
endif()

if (USE_QUICHE)
  # Require quiche when QUICHE path is requested. No curl fallback here.
  if (DEFINED QUICHE_INCLUDE_DIR AND DEFINED QUICHE_LIB)
    message(STATUS "Using vendored quiche at ${QUICHE_INCLUDE_DIR}")
    add_definitions(-DQUICHE_AVAILABLE)
    include_directories(${QUICHE_INCLUDE_DIR})
    list(APPEND SRC_FILES src/transport_quiche.cpp)
    list(APPEND LINK_LIBS ${QUICHE_LIB})
    # Common Linux deps for static Rust libs and quiche
    if (UNIX AND NOT APPLE)
      list(APPEND LINK_LIBS dl pthread m)
    endif()
    # Allow caller to specify additional deps like ssl/crypto paths
    if (DEFINED QUICHE_EXTRA_LIBS)
      message(STATUS "Linking extra quiche libs: ${QUICHE_EXTRA_LIBS}")
      list(APPEND LINK_LIBS ${QUICHE_EXTRA_LIBS})
    endif()
  else()
    message(FATAL_ERROR "USE_QUICHE=ON but QUICHE_INCLUDE_DIR/QUICHE_LIB not set")
  endif()
else()
  # FIXED: Only curl transport
  list(APPEND SRC_FILES src/transport_curl.cpp)
  find_package(CURL REQUIRED)
  list(APPEND LINK_LIBS CURL::libcurl)
endif()

add_executable(vix_cpp_fuse ${SRC_FILES})
target_include_directories(vix_cpp_fuse PRIVATE ${FUSE3_INCLUDE_DIRS})
if (USE_PROTOBUF)
  # Generated fs.pb.h/fs.pb.cc land in the binary dir; expose it to the target
  target_include_directories(vix_cpp_fuse PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
endif()
target_link_libraries(vix_cpp_fuse PRIVATE ${LINK_LIBS} Threads::Threads)

# ---- Packaging & Installation ----
include(InstallRequiredSystemLibraries)

# Install the binary
install(TARGETS vix_cpp_fuse DESTINATION bin)

# Optionally install an extra shared library (e.g., a Rust .so) if provided
# Pass -DVIX_EXTRA_SHARED_LIB=/absolute/path/to/libsomething.so to enable
if (DEFINED VIX_EXTRA_SHARED_LIB AND EXISTS ${VIX_EXTRA_SHARED_LIB})
  install(FILES ${VIX_EXTRA_SHARED_LIB} DESTINATION lib)
endif()

set(CPACK_PACKAGE_NAME "vix-cpp-fuse")
set(CPACK_PACKAGE_VERSION "1.0.0")
set(CPACK_GENERATOR "DEB;RPM")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Vistrix Labs <info@vistrix.in>")
include(CPack)
