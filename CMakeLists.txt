cmake_minimum_required(VERSION 3.16)

project(quicer)

## NIF library ABI version
## Bump manually when ABI changes
set(QUICER_ABI_VERSION 1)

SET(Erlang_EI_INCLUDE_DIRS   ${Erlang_OTP_LIB_DIR}/${Erlang_EI_DIR}/include)
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/priv/)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX ${PROJECT_SOURCE_DIR}/priv/ CACHE PATH "..." FORCE)
endif()

# For cerl picking up the OTP_ROOT
if (DEFINED ENV{Erlang_OTP_ROOT_DIR})
  SET(Erlang_OTP_ROOT_DIR $ENV{Erlang_OTP_ROOT_DIR})
else()
EXECUTE_PROCESS(
        COMMAND         erl -noshell -eval "io:format(\"~s\", [code:root_dir()])" -s erlang halt
        OUTPUT_VARIABLE Erlang_OTP_ROOT_DIR
        )
endif()

if (DEFINED ENV{QUICER_VERSION})
  set(QUICER_VERSION $ENV{QUICER_VERSION})
else()
  set(QUICER_VERSION "0")
endif()

if (DEFINED ENV{CMAKE_BUILD_TYPE})
  set(CMAKE_BUILD_TYPE $ENV{CMAKE_BUILD_TYPE})
else()
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

if (DEFINED ENV{QUICER_USE_OPENSSL3})
  message(STATUS "Use openssl3")
  set(QUIC_TLS "openssl3")
endif()

if (DEFINED ENV{QUIC_ENABLE_LOGGING})
  set(QUIC_ENABLE_LOGGING $ENV{QUIC_ENABLE_LOGGING})
  set(QUIC_LOGGING_TYPE lttng)
else()
  set(QUIC_ENABLE_LOGGING "OFF")
endif()

if (DEFINED ENV{QUIC_LOGGING_TYPE})
  set(QUIC_ENABLE_LOGGING "ON")
  set(QUIC_LOGGING_TYPE $ENV{QUIC_LOGGING_TYPE})
  if (${QUIC_LOGGING_TYPE} STREQUAL "stdout")
      add_compile_options(-DQUICER_LOGGING_STDOUT)
  endif()
endif()

if (DEFINED ENV{QUICER_USE_LTTNG} AND  DEFINED ENV{QUICER_USE_SNK})
  message(FATAL_ERROR "QUICER_USE_LTTNG and QUICER_USE_SNK cannot be defined at same time")
endif()

if (DEFINED ENV{QUICER_USE_LTTNG})
  message(STATUS "Test Build with LTTNG, some Snabbkaffe tests will fail")
  add_compile_options(-DQUICER_USE_LTTNG)
endif()

if (DEFINED ENV{QUICER_USE_SNK})
  message(STATUS "Test Build with Snabbkaffe")
  add_compile_options(-DQUICER_USE_SNK)
endif()

if (DEFINED ENV{QUICER_USE_SANITIZERS})
  set(QUIC_ENABLE_SANITIZERS "ON")
  add_compile_options(-O1 -fno-omit-frame-pointer -fsanitize=address,leak,undefined)
  add_link_options(-O1 -fno-omit-frame-pointer -fsanitize=address,leak,undefined)
endif()

set(QUIC_BUILD_TEST "OFF")
set(QUIC_BUILD_TOOLS "OFF")
set(QUIC_BUILD_PERF "OFF")

set(QUIC_TLS_SECRETS_SUPPORT "ON")

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quicer_vsn.hrl.in
    ${CMAKE_CURRENT_SOURCE_DIR}/include/quicer_vsn.hrl
)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/c_src/quicer_vsn.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/c_src/quicer_vsn.h
)

# src files
set(SOURCES
  c_src/quicer_nif.c
  c_src/quicer_nif.h
  c_src/quicer_eterms.h
  c_src/quicer_reg.c
  c_src/quicer_reg.h
  c_src/quicer_config.c
  c_src/quicer_config.h
  c_src/quicer_queue.c
  c_src/quicer_queue.h
  c_src/quicer_ctx.c
  c_src/quicer_ctx.h
  c_src/quicer_listener.c
  c_src/quicer_listener.h
  c_src/quicer_tls.c
  c_src/quicer_tls.h
  c_src/quicer_connection.c
  c_src/quicer_connection.h
  c_src/quicer_stream.c
  c_src/quicer_stream.h
  c_src/quicer_dgram.c
  c_src/quicer_dgram.h
  c_src/quicer_tp.c
  c_src/quicer_tp.h
  )

# @todo remove -DSO_ATTACH_REUSEPORT_CBPF=51
add_compile_options(-DSO_ATTACH_REUSEPORT_CBPF=51)

# for lttng, quicer_tp.h
include_directories(c_src)
# for templ files
include_directories(${CMAKE_CURRENT_BINARY_DIR}/c_src/)
add_subdirectory(msquic)

add_library(quicer_static STATIC ${SOURCES})
target_include_directories(quicer_static PRIVATE ${Erlang_OTP_ROOT_DIR}/usr/include/ msquic/src/inc/)
if (CMAKE_SYSTEM_NAME MATCHES Linux)
  # note, the value of ${ATOMIC} and %{NUMA} will be set by msquic
  if (NUMA)
    set(MY_NUMA ${NUMA})
  else()
    set(MY_NUMA "")
  endif()
  target_link_libraries(quicer_static PRIVATE core platform inc warnings logging ${ATOMIC} ${MY_NUMA} "-Wl,--no-gc-sections")
elseif (CMAKE_SYSTEM_NAME MATCHES Darwin)
  target_link_libraries(quicer_static PRIVATE core platform inc warnings "-Wl,-undefined,dynamic_lookup -Wl,-dead_strip")
endif()

# @todo clean compiler warnings in the code
target_compile_options(quicer_static PUBLIC "-ggdb3")

if (DEFINED ENV{QUICER_TEST_COVER})
  add_compile_options("-fprofile-arcs" "-ftest-coverage")
  add_link_options("-fprofile-arcs" "-lgcov")
endif()

add_library(quicer_nif SHARED ${SOURCES})

# for macOS Workaround to use opensslquic head files.
target_include_directories(quicer_nif PUBLIC "c_build/_deps/opensslquic-build/openssl/include")

if (CMAKE_SYSTEM_NAME MATCHES Linux)
  target_link_libraries(quicer_nif PRIVATE quicer_static "-Wl,--no-gc-sections -pthread") # no gc because of erlang nif symbols
elseif (CMAKE_SYSTEM_NAME MATCHES Darwin)
  target_link_libraries(quicer_nif PRIVATE quicer_static "-Wl,-undefined,dynamic_lookup -Wl,-dead_strip") # link enif lib
endif()
target_include_directories(quicer_nif PRIVATE ${Erlang_OTP_ROOT_DIR}/usr/include/ msquic/src/inc/)

add_dependencies(quicer_nif quicer_static)
add_dependencies(quicer_static msquic)

set_target_properties(quicer_nif
    PROPERTIES
        LIBRARY_OUTPUT_NAME quicer_nif
        VERSION ${QUICER_ABI_VERSION}-${QUICER_VERSION}
)
include(GNUInstallDirs)
install(TARGETS quicer_nif LIBRARY DESTINATION ${PROJECT_SOURCE_DIR}/priv/)

