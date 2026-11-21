cmake_minimum_required(VERSION 3.21)
project(aegis VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(AEGIS_WITH_YARA "Link libyara and run the rules/yara rules" ON)
option(AEGIS_BUILD_TESTS "Build the unit tests" ON)

# Static CRT (pairs with the x64-windows-static vcpkg triplet): one self-contained exe.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# ---- Portable logic (no Windows headers): unit-tested on every platform ----
add_library(aegis_logic STATIC
  src/logic/strutil.cpp
  src/logic/rulemeta.cpp
  src/logic/report.cpp
  src/logic/privacy.cpp
  src/logic/match.cpp)
target_include_directories(aegis_logic PUBLIC src)
if(MSVC)
  target_compile_options(aegis_logic PRIVATE /W4 /utf-8)
else()
  target_compile_options(aegis_logic PRIVATE -Wall -Wextra)
endif()

# ---- Rule and data files compiled into the binary ----
set(AEGIS_EMBEDDED_FILES
  rules/behavior/aegis-core.yaml
  rules/behavior/destiny.yaml
  rules/behavior/forsaken.yaml
  rules/behavior/generic-external.yaml
  rules/sigma/destiny_hidden_worker.yml
  rules/sigma/destiny_powershell_reflective_loader.yml
  rules/yara/destiny.yar
  rules/yara/forsaken.yar
  data/handle_allowlist.tsv
  data/vulnerable_drivers.tsv
  data/cheat_domains.tsv)
set(AEGIS_EMBEDDED_DEPS "")
foreach(f IN LISTS AEGIS_EMBEDDED_FILES)
  list(APPEND AEGIS_EMBEDDED_DEPS "${CMAKE_CURRENT_SOURCE_DIR}/${f}")
endforeach()
set(AEGIS_EMBEDDED_CPP "${CMAKE_CURRENT_BINARY_DIR}/embedded_data.cpp")
add_custom_command(
  OUTPUT "${AEGIS_EMBEDDED_CPP}"
  COMMAND ${CMAKE_COMMAND} "-DOUT=${AEGIS_EMBEDDED_CPP}" "-DROOT=${CMAKE_CURRENT_SOURCE_DIR}"
          "-DFILES=${AEGIS_EMBEDDED_FILES}" -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed.cmake"
  DEPENDS ${AEGIS_EMBEDDED_DEPS} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/embed.cmake"
  COMMENT "Embedding rules and data"
  VERBATIM)

# ---- The Windows client ----
if(WIN32)
  add_executable(aegis
    src/main.cpp
    src/win/winutil.cpp
    src/win/context.cpp
    src/win/eventlog.cpp
    src/win/handles.cpp
    src/win/etw.cpp
    src/win/system.cpp
    src/win/tamper.cpp
    src/win/artifacts.cpp
    src/win/yara_engine.cpp
    "${AEGIS_EMBEDDED_CPP}")
  target_compile_definitions(aegis PRIVATE UNICODE _UNICODE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
  target_link_libraries(aegis PRIVATE aegis_logic
    advapi32 bcrypt crypt32 wintrust tdh wevtapi iphlpapi ws2_32 shell32 ole32 user32)

  if(MSVC)
    target_compile_options(aegis PRIVATE /W4 /utf-8 /permissive- /guard:cf)
    target_link_options(aegis PRIVATE /guard:cf /DYNAMICBASE /HIGHENTROPYVA /CETCOMPAT)
  else()
    # MinGW: static runtime so AEGIS loads only Windows system DLLs (MicrosoftSignedOnly policy).
    target_compile_options(aegis PRIVATE -Wall -Wextra -Wno-cast-function-type -Wno-missing-field-initializers -municode)
    target_link_options(aegis PRIVATE -municode -static -static-libgcc -static-libstdc++)
  endif()

  if(AEGIS_WITH_YARA)
    find_package(unofficial-libyara CONFIG QUIET)
    if(TARGET unofficial::libyara::libyara)
      target_link_libraries(aegis PRIVATE unofficial::libyara::libyara)
    else()
      # Fallback for a hand-built libyara: -DYARA_ROOT=<prefix with include/ and lib/>
      find_path(YARA_INCLUDE_DIR yara.h HINTS "${YARA_ROOT}/include" REQUIRED)
      find_library(YARA_LIBRARY NAMES yara libyara HINTS "${YARA_ROOT}/lib" REQUIRED)
      target_include_directories(aegis PRIVATE "${YARA_INCLUDE_DIR}")
      target_link_libraries(aegis PRIVATE "${YARA_LIBRARY}")
    endif()
    target_compile_definitions(aegis PRIVATE AEGIS_WITH_YARA)
  endif()
endif()

# ---- Tests ----
if(AEGIS_BUILD_TESTS)
  enable_testing()
  add_executable(aegis_tests tests/unit/test_main.cpp)
  target_link_libraries(aegis_tests PRIVATE aegis_logic)
  target_compile_definitions(aegis_tests PRIVATE AEGIS_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")
  if(MSVC)
    target_compile_options(aegis_tests PRIVATE /utf-8)
  endif()
  add_test(NAME aegis_tests COMMAND aegis_tests)
endif()
