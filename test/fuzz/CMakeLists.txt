# libFuzzer harnesses for quicer's NIF parsing layer.
#
# Enabled from the top-level build with: cmake -DBUILD_FUZZERS=ON ...
# (the parent CMakeLists adds -DQUICER_FUZZ and coverage/sanitizer flags).
#
# Under OSS-Fuzz / ClusterFuzzLite the harnesses are built by
# .clusterfuzzlite/build.sh instead, which links $LIB_FUZZING_ENGINE.

# Local builds link clang's own libFuzzer driver; ClusterFuzzLite/OSS-Fuzz
# builds link the infra-provided engine ($LIB_FUZZING_ENGINE).
if (FUZZ_CFLITE)
  set(QUICER_FUZZ_ENGINE "$ENV{LIB_FUZZING_ENGINE}" CACHE STRING
      "Fuzzing engine link flag")
else()
  set(QUICER_FUZZ_ENGINE "-fsanitize=fuzzer" CACHE STRING
      "Fuzzing engine link flag")
endif()

set(QUICER_FUZZ_TARGETS
  fuzz_cred_config
)

foreach(target ${QUICER_FUZZ_TARGETS})
  add_executable(${target}
    ${CMAKE_CURRENT_SOURCE_DIR}/${target}.c
    ${CMAKE_CURRENT_SOURCE_DIR}/nif_shim.c
  )

  target_include_directories(${target} PRIVATE
    ${CMAKE_SOURCE_DIR}/c_src
    ${CMAKE_BINARY_DIR}/c_src
    ${CMAKE_SOURCE_DIR}/msquic/src/inc
    ${Erlang_OTP_ROOT_DIR}/usr/include/
  )

  if (OPENSSL_INCLUDE_DIR)
    target_include_directories(${target} PRIVATE ${OPENSSL_INCLUDE_DIR})
  else()
    target_include_directories(${target} PRIVATE
      "${PROJECT_BINARY_DIR}/_deps/opensslquic-build/${QUIC_TLS_LIB}/include")
  endif()

  # quicer_static pulls in the parser code under test; the msquic platform
  # libs provide CxPlat* (alloc, init). The nif_shim provides enif_*.
  target_link_libraries(${target} PRIVATE
    quicer_static
    core msquic_platform inc
    ${QUICER_FUZZ_ENGINE}
  )

  add_dependencies(${target} quicer_static)
endforeach()
