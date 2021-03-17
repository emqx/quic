cmake_minimum_required(VERSION 3.16)

project(quicer)

SET(Erlang_EI_INCLUDE_DIRS   ${Erlang_OTP_LIB_DIR}/${Erlang_EI_DIR}/include)
SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/priv/)

EXECUTE_PROCESS(
        COMMAND         erl -noshell -eval "io:format(\"~s\", [code:root_dir()])" -s erlang halt
        OUTPUT_VARIABLE Erlang_OTP_ROOT_DIR
        )

if (NOT DEFINED CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE DEBUG)
endif()

if (NOT DEFINED QUIC_ENABLE_LOGGING)
  set(QUIC_ENABLE_LOGGING ON)
endif()

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
  )

add_subdirectory(submodules/msquic)

add_library(quicer_static STATIC ${SOURCES})
target_include_directories(quicer_static PRIVATE ${Erlang_OTP_ROOT_DIR}/usr/include/ submodules/msquic/src/inc/)
if (CMAKE_SYSTEM_NAME MATCHES Linux)
  target_link_libraries(quicer_static PRIVATE core platform inc warnings "-Wl,--no-gc-sections")
elseif (CMAKE_SYSTEM_NAME MATCHES Darwin)
  target_link_libraries(quicer_static PRIVATE core platform inc warnings "-Wl,-undefined,dynamic_lookup -Wl,-dead_strip")
endif()
# @todo clean complier warnings in the code
target_compile_options(quicer_static PUBLIC "-g" "-Wno-unused-variable")

add_library(quicer_nif SHARED ${SOURCES})
if (CMAKE_SYSTEM_NAME MATCHES Linux)
  target_link_libraries(quicer_nif PRIVATE quicer_static  "-Wl,--no-gc-sections") # no gc because of erlang nif symbols
elseif (CMAKE_SYSTEM_NAME MATCHES Darwin)
  target_link_libraries(quicer_nif PRIVATE quicer_static "-Wl,-undefined,dynamic_lookup -Wl,-dead_strip") # link enif lib
endif()
target_include_directories(quicer_nif PRIVATE ${Erlang_OTP_ROOT_DIR}/usr/include/ submodules/msquic/src/inc/)

add_dependencies(quicer_nif quicer_static)
add_dependencies(quicer_static msquic)

set_target_properties(quicer_nif
    PROPERTIES
        LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/priv/
)
