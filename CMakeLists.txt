cmake_minimum_required(VERSION 3.16)

project(quicer)

SET(Erlang_EI_INCLUDE_DIRS   ${Erlang_OTP_LIB_DIR}/${Erlang_EI_DIR}/include)
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/priv/)

# For cerl picking up the OTP_ROOT
if (DEFINED ENV{Erlang_OTP_ROOT_DIR})
  SET(Erlang_OTP_ROOT_DIR $ENV{Erlang_OTP_ROOT_DIR})
else()
EXECUTE_PROCESS(
        COMMAND         erl -noshell -eval "io:format(\"~s\", [code:root_dir()])" -s erlang halt
        OUTPUT_VARIABLE Erlang_OTP_ROOT_DIR
        )
endif()

if (DEFINED ENV{CMAKE_BUILD_TYPE})
  set(CMAKE_BUILD_TYPE $ENV{CMAKE_BUILD_TYPE})
else()
  set(CMAKE_BUILD_TYPE "RelWithDebInfo")
endif()

if (DEFINED ENV{QUIC_ENABLE_LOGGING})
  set(QUIC_ENABLE_LOGGING $ENV{QUIC_ENABLE_LOGGING})
else()
  set(QUIC_ENABLE_LOGGING "OFF")
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

# src files
set(SOURCES
  c_src/quicer_nif.c
  c_src/quicer_nif.h
  c_src/quicer_eterms.h
  c_src/quicer_config.c
  c_src/quicer_config.h
  c_src/quicer_queue.c
  c_src/quicer_queue.h
  c_src/quicer_ctx.c
  c_src/quicer_ctx.h
  c_src/quicer_listener.c
  c_src/quicer_listener.h
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

add_subdirectory(msquic)

add_library(quicer_static STATIC ${SOURCES})
target_include_directories(quicer_static PRIVATE ${Erlang_OTP_ROOT_DIR}/usr/include/ msquic/src/inc/)
if (CMAKE_SYSTEM_NAME MATCHES Linux)
  # note, the value of ${ATOMIC} will be set by msquic
  target_link_libraries(quicer_static PRIVATE core platform inc warnings logging ${ATOMIC} "-Wl,--no-gc-sections")
elseif (CMAKE_SYSTEM_NAME MATCHES Darwin)
  target_link_libraries(quicer_static PRIVATE core platform inc warnings "-Wl,-undefined,dynamic_lookup -Wl,-dead_strip")
endif()

# @todo clean compiler warnings in the code
target_compile_options(quicer_static PUBLIC "-ggdb3" "-Wno-unused-variable")

if (DEFINED ENV{QUICER_TEST_COVER})
  add_compile_options("-fprofile-arcs" "-ftest-coverage")
  add_link_options("-fprofile-arcs" "-lgcov")
endif()

add_library(quicer_nif SHARED ${SOURCES})
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
        LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/priv/
)

if (QUIC_ENABLE_LOGGING)
  set_target_properties(msquic.lttng PROPERTIES LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/priv)
  set_target_properties(msquic.lttng PROPERTIES LIBRARY_OUTPUT_DIRECTORY_DEBUG ${CMAKE_CURRENT_SOURCE_DIR}/priv)
endif()
