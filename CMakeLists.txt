cmake_minimum_required(VERSION 3.16)
project(callscope VERSION 1.0.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(CALLSCOPE_WERROR "Treat warnings as errors" OFF)
option(CALLSCOPE_SANITIZE "Build with AddressSanitizer and UBSan" OFF)
option(CALLSCOPE_WITH_CURL "Use libcurl for the AI client (falls back to the curl CLI)" ON)
option(CALLSCOPE_BUILD_TESTS "Build unit tests" ON)
option(CALLSCOPE_BUILD_EXAMPLES "Build the demo applications" ON)

set(CS_WARNINGS -Wall -Wextra -Wshadow -Wformat=2 -Wno-unused-parameter)
if(CALLSCOPE_WERROR)
  list(APPEND CS_WARNINGS -Werror)
endif()

if(CALLSCOPE_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

include_directories(${PROJECT_SOURCE_DIR}/include)

# ---------------------------------------------------------------------------
# common: tiny code shared by the analysis library and the runtime hooks
# ---------------------------------------------------------------------------
file(GLOB CS_COMMON_SRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/common/*.c)

# ---------------------------------------------------------------------------
# libcallscope: parsing, analysis, RCA, AI client, reports
# ---------------------------------------------------------------------------
file(GLOB_RECURSE CS_CORE_SRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/core/*.c)
if(CS_CORE_SRC OR CS_COMMON_SRC)
  add_library(callscope STATIC ${CS_COMMON_SRC} ${CS_CORE_SRC})
  target_compile_options(callscope PRIVATE ${CS_WARNINGS})
  target_link_libraries(callscope PUBLIC m)
  if(CALLSCOPE_WITH_CURL)
    find_package(CURL QUIET)
    if(CURL_FOUND)
      target_compile_definitions(callscope PRIVATE CALLSCOPE_HAVE_CURL=1)
      target_link_libraries(callscope PRIVATE CURL::libcurl)
      message(STATUS "callscope: AI client uses libcurl ${CURL_VERSION_STRING}")
    else()
      message(STATUS "callscope: libcurl not found, AI client will use the curl CLI")
    endif()
  endif()
endif()

# ---------------------------------------------------------------------------
# runtime: function tracer (link into instrumented apps) and network shim
# ---------------------------------------------------------------------------
file(GLOB CS_RT_COMMON_SRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/runtime/common/*.c)
file(GLOB CS_RT_TRACE_SRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/runtime/trace/*.c)
file(GLOB CS_RT_NET_SRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/runtime/net/*.c)

if(CS_RT_TRACE_SRC)
  add_library(callscope_trace SHARED ${CS_COMMON_SRC} ${CS_RT_COMMON_SRC} ${CS_RT_TRACE_SRC})
  target_compile_options(callscope_trace PRIVATE ${CS_WARNINGS})
  target_link_libraries(callscope_trace PRIVATE dl pthread)
endif()

if(CS_RT_NET_SRC)
  add_library(callscope_net SHARED ${CS_COMMON_SRC} ${CS_RT_COMMON_SRC} ${CS_RT_NET_SRC})
  target_compile_options(callscope_net PRIVATE ${CS_WARNINGS})
  target_link_libraries(callscope_net PRIVATE dl pthread)
endif()

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
file(GLOB CS_CLI_SRC CONFIGURE_DEPENDS ${PROJECT_SOURCE_DIR}/src/cli/*.c)
if(CS_CLI_SRC AND TARGET callscope)
  add_executable(callscope_cli ${CS_CLI_SRC})
  set_target_properties(callscope_cli PROPERTIES OUTPUT_NAME callscope)
  target_compile_options(callscope_cli PRIVATE ${CS_WARNINGS})
  target_link_libraries(callscope_cli PRIVATE callscope)
  target_compile_definitions(callscope_cli PRIVATE
    CALLSCOPE_VERSION="${PROJECT_VERSION}"
    CALLSCOPE_NET_LIB_BUILD="$<TARGET_FILE_DIR:callscope_cli>/libcallscope_net.so")
  install(TARGETS callscope_cli RUNTIME DESTINATION bin)
endif()

if(TARGET callscope_trace)
  install(TARGETS callscope_trace LIBRARY DESTINATION lib)
endif()
if(TARGET callscope_net)
  install(TARGETS callscope_net LIBRARY DESTINATION lib)
endif()
install(DIRECTORY include/callscope DESTINATION include)

# ---------------------------------------------------------------------------
# tests and examples
# ---------------------------------------------------------------------------
if(CALLSCOPE_BUILD_TESTS AND EXISTS ${PROJECT_SOURCE_DIR}/tests/CMakeLists.txt)
  enable_testing()
  add_subdirectory(tests)
endif()

if(CALLSCOPE_BUILD_EXAMPLES AND EXISTS ${PROJECT_SOURCE_DIR}/examples/CMakeLists.txt)
  add_subdirectory(examples)
endif()
