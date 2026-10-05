cmake_minimum_required(VERSION 3.14)
project(runner LANGUAGES CXX)

option(FUZEVPN_ALLOW_PORTABLE_DEV
  "Allow paired unsigned local VPN test executables outside a protected installation" OFF)
if(FUZEVPN_ALLOW_PORTABLE_DEV)
  message(WARNING "Portable unsigned development broker enabled; this build is for local testing only.")
endif()

# Define the application target. To change its name, change BINARY_NAME in the
# top-level CMakeLists.txt, not the value here, or `flutter run` will no longer
# work.
#
# Any new source files that you add to the application should be added here.
add_executable(${BINARY_NAME} WIN32
  "diagnostics_store.cpp"
  "diagnostics_snapshot.cpp"
  "diagnostics_snapshot_encoding.cpp"
  "diagnostics_network.cpp"
  "api_bootstrap_resolver.cpp"
  "distribution_mode.cpp"
  "portable_runtime.cpp"
  "portable_runtime_client.cpp"
  "flutter_window.cpp"
  "main.cpp"
  "maintenance_state.cpp"
  "maintenance_network_state.cpp"
  "network_protection.cpp"
  "secure_store_channel.cpp"
  "openvpn_tunnel.cpp"
  "privileged_broker.cpp"
  "privileged_runtime.cpp"
  "wireguard_tunnel.cpp"
  "utils.cpp"
  "update_channel.cpp"
  "update_security.cpp"
  "portable_update.cpp"
  "miniz_inflate.cpp"
  "win32_window.cpp"
  "${FLUTTER_MANAGED_DIR}/generated_plugin_registrant.cc"
  "Runner.rc"
  "runner.exe.manifest"
)

# The privileged runtime is a separate native executable. It reuses Flutter's
# small, source-built StandardMethodCodec only as the existing IPC wire format;
# it does not link flutter_windows.dll or any UI/plugin library.
set(FUZEVPN_FLUTTER_WRAPPER_DIR
    "${FLUTTER_MANAGED_DIR}/ephemeral/cpp_client_wrapper")
set_source_files_properties(
  "${FUZEVPN_FLUTTER_WRAPPER_DIR}/standard_codec.cc"
  PROPERTIES GENERATED TRUE)
add_library(fuzevpn_service_codec STATIC
  "${FUZEVPN_FLUTTER_WRAPPER_DIR}/standard_codec.cc")
set_target_properties(fuzevpn_service_codec PROPERTIES
  ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/native-libs")
apply_standard_settings(fuzevpn_service_codec)
target_include_directories(fuzevpn_service_codec PUBLIC
  "${FUZEVPN_FLUTTER_WRAPPER_DIR}/include")
add_dependencies(fuzevpn_service_codec flutter_assemble)

add_executable(${FUZEVPN_SERVICE_TARGET} WIN32
  "diagnostics_snapshot.cpp"
  "diagnostics_snapshot_encoding.cpp"
  "diagnostics_network.cpp"
  "api_bootstrap_resolver.cpp"
  "distribution_mode.cpp"
  "portable_runtime.cpp"
  "portable_runtime_client.cpp"
  "update_security.cpp"
  "service_main.cpp"
  "maintenance_state.cpp"
  "maintenance_network_state.cpp"
  "network_protection.cpp"
  "secure_store_channel.cpp"
  "openvpn_tunnel.cpp"
  "privileged_broker.cpp"
  "privileged_runtime.cpp"
  "wireguard_tunnel.cpp"
  "Runner.rc"
  "service.exe.manifest")
set_target_properties(${FUZEVPN_SERVICE_TARGET} PROPERTIES
  OUTPUT_NAME "fuzevpn-service")
apply_standard_settings(${FUZEVPN_SERVICE_TARGET})
target_compile_features(${FUZEVPN_SERVICE_TARGET} PRIVATE cxx_std_20)
target_compile_definitions(${FUZEVPN_SERVICE_TARGET} PRIVATE
  "NOMINMAX" "WIN32_LEAN_AND_MEAN" "FUZEVPN_SERVICE_PROCESS"
  CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
  "FUZEVPN_ALLOW_PORTABLE_DEV=$<BOOL:${FUZEVPN_ALLOW_PORTABLE_DEV}>"
  "FLUTTER_VERSION_MAJOR=${FLUTTER_VERSION_MAJOR}"
  "FLUTTER_VERSION_MINOR=${FLUTTER_VERSION_MINOR}"
  "FLUTTER_VERSION_PATCH=${FLUTTER_VERSION_PATCH}"
  "FLUTTER_VERSION_BUILD=0"
  "FUZEVPN_INTERNAL_NAME=\"fuzevpn-service\""
  "FUZEVPN_ORIGINAL_FILENAME=\"fuzevpn-service.exe\""
  "FUZEVPN_FILE_DESCRIPTION=\"FuzeVPN service\"")
target_link_libraries(${FUZEVPN_SERVICE_TARGET} PRIVATE
  fuzevpn_service_codec
  "crypt32.lib" "shell32.lib" "advapi32.lib" "fwpuclnt.lib"
  "iphlpapi.lib" "rpcrt4.lib" "ws2_32.lib" "wintrust.lib" "bcrypt.lib" "version.lib" "ole32.lib" "msi.lib")
target_include_directories(${FUZEVPN_SERVICE_TARGET} PRIVATE
  "${CMAKE_SOURCE_DIR}")

# Small signed elevation entry point. It has no Flutter/VPN DLL imports and
# exits as soon as the verified installer is launched from protected storage.
add_executable(fuzevpn_update WIN32 "update_main.cpp" "update_security.cpp" "distribution_mode.cpp"
  "portable_update.cpp" "portable_runtime.cpp" "miniz_inflate.cpp"
  "Runner.rc" "update.exe.manifest")
apply_standard_settings(fuzevpn_update)
set_target_properties(fuzevpn_update PROPERTIES OUTPUT_NAME "fuzevpn-update"
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_compile_definitions(fuzevpn_update PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN
  CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
  "FLUTTER_VERSION_MAJOR=${FLUTTER_VERSION_MAJOR}"
  "FLUTTER_VERSION_MINOR=${FLUTTER_VERSION_MINOR}"
  "FLUTTER_VERSION_PATCH=${FLUTTER_VERSION_PATCH}"
  "FLUTTER_VERSION_BUILD=0"
  "FUZEVPN_INTERNAL_NAME=\"fuzevpn-update\""
  "FUZEVPN_ORIGINAL_FILENAME=\"fuzevpn-update.exe\""
  "FUZEVPN_FILE_DESCRIPTION=\"FuzeVPN update\"")
target_compile_options(fuzevpn_update PRIVATE
  "$<$<CONFIG:Debug>:/MTd>" "$<$<NOT:$<CONFIG:Debug>>:/MT>")
target_link_libraries(fuzevpn_update PRIVATE advapi32 bcrypt crypt32 shell32 ole32 wintrust version msi)
target_link_options(fuzevpn_update PRIVATE /DEPENDENTLOADFLAG:0x800)
add_dependencies(${BINARY_NAME} fuzevpn_update)

set_source_files_properties("miniz_inflate.cpp" PROPERTIES
  COMPILE_OPTIONS "/W3;/WX-;/utf-8")

# The portable bootstrap must import only OS DLLs before its entry point:
# static CRT plus System32-only dependent library resolution by the loader.
add_executable(fuzevpn_runtime WIN32 "portable_runtime_main.cpp"
  "portable_runtime.cpp" "portable_service_lease.cpp" "update_security.cpp" "Runner.rc" "runtime.exe.manifest")
apply_standard_settings(fuzevpn_runtime)
set_target_properties(fuzevpn_runtime PROPERTIES OUTPUT_NAME "fuzevpn-runtime"
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
target_compile_options(fuzevpn_runtime PRIVATE
  "$<$<CONFIG:Debug>:/MTd>" "$<$<NOT:$<CONFIG:Debug>>:/MT>")
target_link_options(fuzevpn_runtime PRIVATE /DEPENDENTLOADFLAG:0x800)
target_compile_definitions(fuzevpn_runtime PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN
  CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
  "FUZEVPN_ALLOW_PORTABLE_DEV=$<BOOL:${FUZEVPN_ALLOW_PORTABLE_DEV}>"
  "FLUTTER_VERSION_MAJOR=${FLUTTER_VERSION_MAJOR}"
  "FLUTTER_VERSION_MINOR=${FLUTTER_VERSION_MINOR}"
  "FLUTTER_VERSION_PATCH=${FLUTTER_VERSION_PATCH}"
  "FLUTTER_VERSION_BUILD=0"
  "FUZEVPN_INTERNAL_NAME=\"fuzevpn-runtime\""
  "FUZEVPN_ORIGINAL_FILENAME=\"fuzevpn-runtime.exe\""
  "FUZEVPN_FILE_DESCRIPTION=\"FuzeVPN portable runtime\"")
target_link_libraries(fuzevpn_runtime PRIVATE advapi32 bcrypt crypt32 shell32 ole32 wintrust version)
add_dependencies(${BINARY_NAME} fuzevpn_runtime)

# Manual administrator integration probe, never part of CTest or INSTALL.
# It exercises production signed-service validation, idle SCM handoff and
# restoration without starting a VPN, the GUI or a portable engine.
add_executable(fuzevpn_service_handoff_probe EXCLUDE_FROM_ALL
  "../tests/service_idle_handoff_probe.cpp" "portable_service_lease.cpp"
  "portable_runtime.cpp" "update_security.cpp")
apply_standard_settings(fuzevpn_service_handoff_probe)
set_target_properties(fuzevpn_service_handoff_probe PROPERTIES
  MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>"
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
target_compile_options(fuzevpn_service_handoff_probe PRIVATE
  "$<$<CONFIG:Debug>:/MTd>" "$<$<NOT:$<CONFIG:Debug>>:/MT>")
target_compile_definitions(fuzevpn_service_handoff_probe PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
  "FUZEVPN_ALLOW_PORTABLE_DEV=$<BOOL:${FUZEVPN_ALLOW_PORTABLE_DEV}>")
target_link_libraries(fuzevpn_service_handoff_probe PRIVATE
  advapi32 bcrypt crypt32 shell32 ole32 wintrust version)

# Apply the standard set of build settings. This can be removed for applications
# that need different build settings.
apply_standard_settings(${BINARY_NAME})
target_compile_features(${BINARY_NAME} PRIVATE cxx_std_20)

# Flutter and the network/API surface always run as the signed-in user. Only
# the narrowly scoped native VPN broker is started through UAC when a tunnel
# operation actually needs Windows administrator privileges.

# Add preprocessor definitions for the build version.
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION=\"${FLUTTER_VERSION}\"")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MAJOR=${FLUTTER_VERSION_MAJOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_MINOR=${FLUTTER_VERSION_MINOR}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_PATCH=${FLUTTER_VERSION_PATCH}")
target_compile_definitions(${BINARY_NAME} PRIVATE "FLUTTER_VERSION_BUILD=${FLUTTER_VERSION_BUILD}")

# Disable Windows macros that collide with C++ standard library functions.
target_compile_definitions(${BINARY_NAME} PRIVATE "NOMINMAX" "WIN32_LEAN_AND_MEAN"
  "FUZEVPN_ALLOW_PORTABLE_DEV=$<BOOL:${FUZEVPN_ALLOW_PORTABLE_DEV}>"
  CERT_CHAIN_PARA_HAS_EXTRA_FIELDS)

# Add dependency libraries and include directories. Add any application-specific
# dependencies here.
target_link_libraries(${BINARY_NAME} PRIVATE flutter flutter_wrapper_app)
target_link_libraries(${BINARY_NAME} PRIVATE "dwmapi.lib" "crypt32.lib" "shell32.lib" "advapi32.lib" "msi.lib"
  "fwpuclnt.lib" "iphlpapi.lib" "rpcrt4.lib" "ws2_32.lib" "wintrust.lib"
  "winhttp.lib" "bcrypt.lib" "version.lib" "ole32.lib")
target_include_directories(${BINARY_NAME} PRIVATE "${CMAKE_SOURCE_DIR}")

# OpenVPN 3 Core is vendored inside the Windows project so a clean machine no
# longer depends on the historical Codex workspace layout.
set(FUZEVPN_OPENVPN3_CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/openvpn3-core"
    CACHE PATH "Pinned OpenVPN 3 Core source directory")
option(FUZEVPN_ENABLE_OPENVPN3 "Compile the reviewed OpenVPN 3 Core integration" ON)
if(FUZEVPN_ENABLE_OPENVPN3 AND EXISTS "${FUZEVPN_OPENVPN3_CORE_DIR}/client/ovpncli.cpp")
  set(FUZEVPN_OPENVPN3_VCPKG_DIR
      "${FUZEVPN_OPENVPN3_CORE_DIR}/vcpkg_installed/${FUZEVPN_TARGET_ARCH}-windows")
  if(NOT EXISTS "${FUZEVPN_OPENVPN3_VCPKG_DIR}/include/openssl")
    message(FATAL_ERROR "OpenVPN 3 Core dependencies have not been built for Windows ${FUZEVPN_TARGET_ARCH}.")
  endif()
  file(GLOB FUZEVPN_SSL_DLL_CANDIDATES "${FUZEVPN_OPENVPN3_VCPKG_DIR}/bin/libssl-3*.dll")
  file(GLOB FUZEVPN_CRYPTO_DLL_CANDIDATES "${FUZEVPN_OPENVPN3_VCPKG_DIR}/bin/libcrypto-3*.dll")
  list(LENGTH FUZEVPN_SSL_DLL_CANDIDATES FUZEVPN_SSL_DLL_COUNT)
  list(LENGTH FUZEVPN_CRYPTO_DLL_CANDIDATES FUZEVPN_CRYPTO_DLL_COUNT)
  if(NOT FUZEVPN_SSL_DLL_COUNT EQUAL 1 OR NOT FUZEVPN_CRYPTO_DLL_COUNT EQUAL 1)
    message(FATAL_ERROR "Exactly one OpenSSL 3 DLL pair is required for ${FUZEVPN_TARGET_ARCH}.")
  endif()
  list(GET FUZEVPN_SSL_DLL_CANDIDATES 0 FUZEVPN_SSL_DLL_PATH)
  list(GET FUZEVPN_CRYPTO_DLL_CANDIDATES 0 FUZEVPN_CRYPTO_DLL_PATH)
  get_filename_component(FUZEVPN_SSL_DLL_NAME "${FUZEVPN_SSL_DLL_PATH}" NAME)
  get_filename_component(FUZEVPN_CRYPTO_DLL_NAME "${FUZEVPN_CRYPTO_DLL_PATH}" NAME)
  add_compile_definitions(
    "FUZEVPN_OPENSSL_SSL_DLL=\"${FUZEVPN_SSL_DLL_NAME}\""
    "FUZEVPN_OPENSSL_CRYPTO_DLL=\"${FUZEVPN_CRYPTO_DLL_NAME}\"")
  set(FUZEVPN_OPENSSL_VERSION_FILE
      "${FUZEVPN_OPENVPN3_VCPKG_DIR}/share/openssl/OpenSSLConfigVersion.cmake")
  if(NOT EXISTS "${FUZEVPN_OPENSSL_VERSION_FILE}")
    message(FATAL_ERROR "The pinned OpenSSL version metadata is missing.")
  endif()
  file(READ "${FUZEVPN_OPENSSL_VERSION_FILE}" FUZEVPN_OPENSSL_VERSION_METADATA)
  if(NOT FUZEVPN_OPENSSL_VERSION_METADATA MATCHES
      "set\\(PACKAGE_VERSION 3\\.6\\.5\\)")
    message(FATAL_ERROR
      "OpenSSL 3.6.5 is required. Rebuild the pinned vcpkg dependencies.")
  endif()
  set(FUZEVPN_ASIO_VERSION_FILE
      "${FUZEVPN_OPENVPN3_VCPKG_DIR}/include/asio/version.hpp")
  if(NOT EXISTS "${FUZEVPN_ASIO_VERSION_FILE}")
    message(FATAL_ERROR "The pinned Asio version metadata is missing.")
  endif()
  file(READ "${FUZEVPN_ASIO_VERSION_FILE}" FUZEVPN_ASIO_VERSION_METADATA)
  if(NOT FUZEVPN_ASIO_VERSION_METADATA MATCHES
      "#define ASIO_VERSION 103600")
    message(FATAL_ERROR
      "Asio 1.36.0 is required for the reviewed OpenVPN lifecycle.")
  endif()

  add_library(fuzevpn_openvpn_core STATIC
    "openvpn_core_module.cpp"
    "openvpn_dco_driver.cpp"
    "${FUZEVPN_OPENVPN3_CORE_DIR}/openvpn/crypto/data_epoch.cpp"
    "${FUZEVPN_OPENVPN3_CORE_DIR}/openvpn/openssl/xkey/xkey_helper.c"
    "${FUZEVPN_OPENVPN3_CORE_DIR}/openvpn/openssl/xkey/xkey_provider.c")
  set_target_properties(fuzevpn_openvpn_core PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/native-libs")
  target_compile_features(fuzevpn_openvpn_core PRIVATE cxx_std_20)
  set(FUZEVPN_OPENVPN3_DEFINITIONS
    FUZEVPN_ENABLE_OPENVPN3_CORE
    OPENVPN_CORE_API_VISIBILITY_HIDDEN
    ASIO_STANDALONE
    USE_ASIO
    HAVE_LZ4
    USE_OPENSSL
    ENABLE_OVPNDCOWIN
    _WIN32_WINNT=0x0600
    TAP_WIN_COMPONENT_ID=tap0901
    _CRT_SECURE_NO_WARNINGS
    ASIO_DISABLE_LOCAL_SOCKETS
    ENABLE_EXTERNAL_PKI
    FMT_SHARED
    NOMINMAX
    _HAS_EXCEPTIONS=1)
  target_include_directories(fuzevpn_openvpn_core PRIVATE
    "${FUZEVPN_OPENVPN3_CORE_DIR}"
    "${FUZEVPN_OPENVPN3_VCPKG_DIR}/include")
  target_link_libraries(fuzevpn_openvpn_core PRIVATE
    debug "${FUZEVPN_OPENVPN3_VCPKG_DIR}/debug/lib/lz4d.lib"
    optimized "${FUZEVPN_OPENVPN3_VCPKG_DIR}/lib/lz4.lib"
    debug "${FUZEVPN_OPENVPN3_VCPKG_DIR}/debug/lib/fmtd.lib"
    optimized "${FUZEVPN_OPENVPN3_VCPKG_DIR}/lib/fmt.lib"
    debug "${FUZEVPN_OPENVPN3_VCPKG_DIR}/debug/lib/libssl.lib"
    optimized "${FUZEVPN_OPENVPN3_VCPKG_DIR}/lib/libssl.lib"
    debug "${FUZEVPN_OPENVPN3_VCPKG_DIR}/debug/lib/libcrypto.lib"
    optimized "${FUZEVPN_OPENVPN3_VCPKG_DIR}/lib/libcrypto.lib"
    "fwpuclnt.lib" "iphlpapi.lib" "wininet.lib" "setupapi.lib"
    "rpcrt4.lib" "wtsapi32.lib" "bcrypt.lib" "newdev.lib" "cfgmgr32.lib")
  set_source_files_properties(
    "openvpn_core_module.cpp"
    "${FUZEVPN_OPENVPN3_CORE_DIR}/openvpn/crypto/data_epoch.cpp"
    "${FUZEVPN_OPENVPN3_CORE_DIR}/openvpn/openssl/xkey/xkey_helper.c"
    "${FUZEVPN_OPENVPN3_CORE_DIR}/openvpn/openssl/xkey/xkey_provider.c"
    PROPERTIES
      COMPILE_DEFINITIONS "${FUZEVPN_OPENVPN3_DEFINITIONS}"
      COMPILE_OPTIONS "/W3;/WX-;/bigobj;/utf-8;/UUNICODE;/U_UNICODE")
  target_compile_definitions(${BINARY_NAME} PRIVATE FUZEVPN_ENABLE_OPENVPN3_CORE)
  target_link_libraries(${BINARY_NAME} PRIVATE fuzevpn_openvpn_core)
  target_compile_definitions(${FUZEVPN_SERVICE_TARGET} PRIVATE
    FUZEVPN_ENABLE_OPENVPN3_CORE)
  target_link_libraries(${FUZEVPN_SERVICE_TARGET} PRIVATE
    fuzevpn_openvpn_core)
  add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "$<IF:$<CONFIG:Debug>,${FUZEVPN_OPENVPN3_VCPKG_DIR}/debug/bin/lz4d.dll,${FUZEVPN_OPENVPN3_VCPKG_DIR}/bin/lz4.dll>"
      "$<IF:$<CONFIG:Debug>,$<TARGET_FILE_DIR:${BINARY_NAME}>/lz4d.dll,$<TARGET_FILE_DIR:${BINARY_NAME}>/lz4.dll>"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "$<IF:$<CONFIG:Debug>,${FUZEVPN_OPENVPN3_VCPKG_DIR}/debug/bin/${FUZEVPN_SSL_DLL_NAME},${FUZEVPN_OPENVPN3_VCPKG_DIR}/bin/${FUZEVPN_SSL_DLL_NAME}>"
      "$<TARGET_FILE_DIR:${BINARY_NAME}>/${FUZEVPN_SSL_DLL_NAME}"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "$<IF:$<CONFIG:Debug>,${FUZEVPN_OPENVPN3_VCPKG_DIR}/debug/bin/${FUZEVPN_CRYPTO_DLL_NAME},${FUZEVPN_OPENVPN3_VCPKG_DIR}/bin/${FUZEVPN_CRYPTO_DLL_NAME}>"
      "$<TARGET_FILE_DIR:${BINARY_NAME}>/${FUZEVPN_CRYPTO_DLL_NAME}")
  if(FUZEVPN_TARGET_ARCH STREQUAL "x64")
    set(FUZEVPN_DRIVER_ARCH "amd64")
  else()
    set(FUZEVPN_DRIVER_ARCH "arm64")
  endif()
  set(OPENVPN_DCO_RUNTIME_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/openvpn-dco/2.8.7")
  set(OPENVPN_DCO_RUNTIME_DIR "${OPENVPN_DCO_RUNTIME_ROOT}/${FUZEVPN_DRIVER_ARCH}")
  if(NOT EXISTS "${OPENVPN_DCO_RUNTIME_DIR}/win10/ovpn-dco.inf" OR
     NOT EXISTS "${OPENVPN_DCO_RUNTIME_DIR}/win11/ovpn-dco.inf")
    message(FATAL_ERROR "The signed OpenVPN DCO driver package is missing.")
  endif()
  add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
      "${OPENVPN_DCO_RUNTIME_DIR}"
      "$<TARGET_FILE_DIR:${BINARY_NAME}>/openvpn-dco"
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "${OPENVPN_DCO_RUNTIME_ROOT}/NOTICE.md"
      "$<TARGET_FILE_DIR:${BINARY_NAME}>/openvpn-dco/NOTICE.md")
else()
  message(STATUS "OpenVPN 3 Core unavailable: OpenVPN stays disabled in this build.")
endif()

# The official embeddable WireGuard runtime is copied beside the executable.
# FuzeVPN dynamically loads it; customers do not install WireGuard.
if(FUZEVPN_TARGET_ARCH STREQUAL "x64")
  set(FUZEVPN_DRIVER_ARCH "amd64")
else()
  set(FUZEVPN_DRIVER_ARCH "arm64")
endif()
set(WIREGUARD_RUNTIME_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/wireguard/1.1/${FUZEVPN_DRIVER_ARCH}")
set(WIREGUARD_NOTICE_FILE "${CMAKE_CURRENT_SOURCE_DIR}/../../third_party/wireguard/1.1/NOTICE.md")
add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${WIREGUARD_RUNTIME_DIR}/tunnel.dll"
    "$<TARGET_FILE_DIR:${BINARY_NAME}>/tunnel.dll"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${WIREGUARD_RUNTIME_DIR}/wireguard.dll"
    "$<TARGET_FILE_DIR:${BINARY_NAME}>/wireguard.dll"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${WIREGUARD_NOTICE_FILE}"
    "$<TARGET_FILE_DIR:${BINARY_NAME}>/WIREGUARD_NOTICE.md"
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${CMAKE_CURRENT_SOURCE_DIR}/resources/app_icon.ico"
    "$<TARGET_FILE_DIR:${BINARY_NAME}>/fuzevpn_tray.ico"
)

add_custom_command(TARGET ${BINARY_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND}
    "-DSOURCE_ROOT=${CMAKE_CURRENT_SOURCE_DIR}/../.."
    "-DBUNDLE_DIR=$<TARGET_FILE_DIR:${BINARY_NAME}>"
    "-DOPENVPN_ENABLED=${FUZEVPN_ENABLE_OPENVPN3}"
    "-DOPENVPN_VCPKG_DIR=${FUZEVPN_OPENVPN3_VCPKG_DIR}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/../../tools/package-native-notices.cmake"
  VERBATIM)

# Run the Flutter tool portions of the build. This must not be removed.
add_dependencies(${BINARY_NAME} flutter_assemble)
add_dependencies(${FUZEVPN_SERVICE_TARGET} flutter_assemble)

# Isolated regression executables never start a VPN, install a service or
# modify Windows filtering. Keep them out of the distributed application.
add_executable(fuzevpn_runtime_architecture_test EXCLUDE_FROM_ALL
  "../tests/runtime_architecture_test.cpp")
apply_standard_settings(fuzevpn_runtime_architecture_test)
target_compile_definitions(fuzevpn_runtime_architecture_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_include_directories(fuzevpn_runtime_architecture_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(fuzevpn_runtime_architecture_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME runtime_architecture COMMAND fuzevpn_runtime_architecture_test)
set_tests_properties(runtime_architecture PROPERTIES TIMEOUT 10)

add_executable(fuzevpn_native_security_test EXCLUDE_FROM_ALL
  "tests/native_security_test.cpp"
  "tests/native_store_test_support.cpp"
  "tests/maintenance_state_test_support.cpp"
  "tests/maintenance_network_test_support.cpp"
  "tests/portable_service_lease_test_support.cpp"
  "distribution_mode.cpp"
  "portable_runtime.cpp"
  "portable_runtime_client.cpp"
  "update_security.cpp"
  "maintenance_state.cpp"
  "maintenance_network_state.cpp"
  "privileged_runtime.cpp")
apply_standard_settings(fuzevpn_native_security_test)
target_compile_features(fuzevpn_native_security_test PRIVATE cxx_std_20)
target_compile_definitions(fuzevpn_native_security_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN
  CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
  "FUZEVPN_ALLOW_PORTABLE_DEV=$<BOOL:${FUZEVPN_ALLOW_PORTABLE_DEV}>")
target_include_directories(fuzevpn_native_security_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_SOURCE_DIR}"
  "${FLUTTER_MANAGED_DIR}/ephemeral")
target_link_libraries(fuzevpn_native_security_test PRIVATE
  fuzevpn_service_codec crypt32 shell32 advapi32 fwpuclnt
  iphlpapi rpcrt4 ws2_32 wintrust ole32 bcrypt version msi)
set_target_properties(fuzevpn_native_security_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME native_security COMMAND fuzevpn_native_security_test)
set_tests_properties(native_security PROPERTIES TIMEOUT 45)

add_executable(fuzevpn_update_security_test EXCLUDE_FROM_ALL
  "../tests/update_security_test.cpp" "update_security.cpp")
apply_standard_settings(fuzevpn_update_security_test)
target_compile_definitions(fuzevpn_update_security_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN
  CERT_CHAIN_PARA_HAS_EXTRA_FIELDS)
target_include_directories(fuzevpn_update_security_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(fuzevpn_update_security_test PRIVATE
  advapi32 bcrypt crypt32 shell32 ole32 wintrust version)
set_target_properties(fuzevpn_update_security_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME update_security COMMAND fuzevpn_update_security_test
  "${CMAKE_BINARY_DIR}/native-tests/update-fixtures")
set_tests_properties(update_security PROPERTIES TIMEOUT 30)

add_executable(fuzevpn_portable_update_test EXCLUDE_FROM_ALL
  "../tests/portable_update_test.cpp" "portable_update.cpp" "portable_runtime.cpp"
  "miniz_inflate.cpp" "update_security.cpp")
apply_standard_settings(fuzevpn_portable_update_test)
target_compile_definitions(fuzevpn_portable_update_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN
  CERT_CHAIN_PARA_HAS_EXTRA_FIELDS FUZEVPN_ALLOW_PORTABLE_DEV=0)
target_include_directories(fuzevpn_portable_update_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(fuzevpn_portable_update_test PRIVATE
  advapi32 bcrypt crypt32 shell32 ole32 wintrust version)
set_target_properties(fuzevpn_portable_update_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME portable_update COMMAND fuzevpn_portable_update_test
  "${CMAKE_BINARY_DIR}/native-tests/portable-update-fixtures")
set_tests_properties(portable_update PROPERTIES TIMEOUT 45)

add_executable(fuzevpn_portable_runtime_test EXCLUDE_FROM_ALL
  "../tests/portable_runtime_test.cpp" "portable_runtime.cpp" "update_security.cpp")
apply_standard_settings(fuzevpn_portable_runtime_test)
target_compile_definitions(fuzevpn_portable_runtime_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN
  CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
  "FUZEVPN_ALLOW_PORTABLE_DEV=$<BOOL:${FUZEVPN_ALLOW_PORTABLE_DEV}>")
target_include_directories(fuzevpn_portable_runtime_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(fuzevpn_portable_runtime_test PRIVATE advapi32 bcrypt crypt32 shell32 ole32 wintrust version)
set_target_properties(fuzevpn_portable_runtime_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME portable_runtime COMMAND fuzevpn_portable_runtime_test
  "${CMAKE_BINARY_DIR}/native-tests/portable-fixtures")
set_tests_properties(portable_runtime PROPERTIES TIMEOUT 45)

# Exercise the production trust branch against the actual unsigned validation
# bundle using --reject-unsigned-bundle after resource preparation.
add_executable(fuzevpn_portable_production_test EXCLUDE_FROM_ALL
  "../tests/portable_runtime_test.cpp" "portable_runtime.cpp" "update_security.cpp")
apply_standard_settings(fuzevpn_portable_production_test)
target_compile_definitions(fuzevpn_portable_production_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN
  CERT_CHAIN_PARA_HAS_EXTRA_FIELDS FUZEVPN_ALLOW_PORTABLE_DEV=0)
target_include_directories(fuzevpn_portable_production_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(fuzevpn_portable_production_test PRIVATE advapi32 bcrypt crypt32 shell32 ole32 wintrust version)
set_target_properties(fuzevpn_portable_production_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")

add_executable(fuzevpn_distribution_mode_test EXCLUDE_FROM_ALL
  "../tests/distribution_mode_test.cpp" "../tests/distribution_mode_discovery_test.cpp" "distribution_mode.cpp")
apply_standard_settings(fuzevpn_distribution_mode_test)
target_compile_definitions(fuzevpn_distribution_mode_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_include_directories(fuzevpn_distribution_mode_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(fuzevpn_distribution_mode_test PRIVATE advapi32 msi)
set_target_properties(fuzevpn_distribution_mode_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME distribution_mode COMMAND fuzevpn_distribution_mode_test)

add_executable(fuzevpn_api_resolver_adapter_test EXCLUDE_FROM_ALL
  "../tests/api_resolver_adapter_test.cpp")
apply_standard_settings(fuzevpn_api_resolver_adapter_test)
target_compile_features(fuzevpn_api_resolver_adapter_test PRIVATE cxx_std_20)
target_compile_definitions(fuzevpn_api_resolver_adapter_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(fuzevpn_api_resolver_adapter_test PRIVATE advapi32 ws2_32 iphlpapi)
set_target_properties(fuzevpn_api_resolver_adapter_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME api_resolver_adapters COMMAND fuzevpn_api_resolver_adapter_test)
set_tests_properties(api_resolver_adapters PROPERTIES TIMEOUT 10)

add_executable(fuzevpn_diagnostics_snapshot_test EXCLUDE_FROM_ALL
  "../tests/diagnostics_snapshot_test.cpp"
  "diagnostics_snapshot_encoding.cpp" "diagnostics_network.cpp")
apply_standard_settings(fuzevpn_diagnostics_snapshot_test)
target_compile_features(fuzevpn_diagnostics_snapshot_test PRIVATE cxx_std_20)
target_compile_definitions(fuzevpn_diagnostics_snapshot_test PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN FUZEVPN_SERVICE_PROCESS)
target_include_directories(fuzevpn_diagnostics_snapshot_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}" "${FUZEVPN_FLUTTER_WRAPPER_DIR}/include")
target_link_libraries(fuzevpn_diagnostics_snapshot_test PRIVATE iphlpapi ws2_32 advapi32)
set_target_properties(fuzevpn_diagnostics_snapshot_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME diagnostics_snapshot COMMAND fuzevpn_diagnostics_snapshot_test)
set_tests_properties(diagnostics_snapshot PROPERTIES TIMEOUT 30)

add_executable(fuzevpn_diagnostics_store_test EXCLUDE_FROM_ALL
  "../tests/diagnostics_store_test.cpp" "diagnostics_store.cpp")
apply_standard_settings(fuzevpn_diagnostics_store_test)
target_compile_definitions(fuzevpn_diagnostics_store_test PRIVATE
  NOMINMAX WIN32_LEAN_AND_MEAN FUZEVPN_DIAGNOSTICS_STORE_NO_CHANNEL)
target_include_directories(fuzevpn_diagnostics_store_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(fuzevpn_diagnostics_store_test PRIVATE crypt32 advapi32 shell32 ole32 bcrypt)
set_target_properties(fuzevpn_diagnostics_store_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME diagnostics_store COMMAND fuzevpn_diagnostics_store_test
  "${CMAKE_BINARY_DIR}/native-tests/diagnostics-fixtures")
set_tests_properties(diagnostics_store PROPERTIES TIMEOUT 60)

add_executable(fuzevpn_network_filter_test EXCLUDE_FROM_ALL
  "../tests/network_filter_test.cpp")
apply_standard_settings(fuzevpn_network_filter_test)
target_compile_definitions(fuzevpn_network_filter_test PRIVATE NOMINMAX)
target_include_directories(fuzevpn_network_filter_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(fuzevpn_network_filter_test PRIVATE
  advapi32 fwpuclnt iphlpapi rpcrt4 wintrust ws2_32)
set_target_properties(fuzevpn_network_filter_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME network_filters COMMAND fuzevpn_network_filter_test)
set_tests_properties(network_filters PROPERTIES TIMEOUT 30)

add_executable(fuzevpn_tray_icon_test EXCLUDE_FROM_ALL
  "../tests/tray_icon_state_test.cpp")
apply_standard_settings(fuzevpn_tray_icon_test)
target_compile_definitions(fuzevpn_tray_icon_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_link_libraries(fuzevpn_tray_icon_test PRIVATE shell32)
set_target_properties(fuzevpn_tray_icon_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME tray_icon COMMAND fuzevpn_tray_icon_test)
set_tests_properties(tray_icon PROPERTIES TIMEOUT 30)

add_executable(fuzevpn_window_geometry_test EXCLUDE_FROM_ALL
  "../tests/window_geometry_test.cpp")
apply_standard_settings(fuzevpn_window_geometry_test)
target_compile_definitions(fuzevpn_window_geometry_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN)
target_include_directories(fuzevpn_window_geometry_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
set_target_properties(fuzevpn_window_geometry_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
add_test(NAME window_geometry COMMAND fuzevpn_window_geometry_test)

# Manually invoked passive Flutter bridge probe; never part of CTest/INSTALL.
# It loads a separate diagnostic Dart AOT entrypoint, not the application.
get_target_property(FUZEVPN_STARTUP_PROBE_SOURCES ${BINARY_NAME} SOURCES)
list(REMOVE_ITEM FUZEVPN_STARTUP_PROBE_SOURCES "main.cpp" "diagnostics_store.cpp")
add_executable(fuzevpn_startup_bridge_test WIN32 EXCLUDE_FROM_ALL
  ${FUZEVPN_STARTUP_PROBE_SOURCES} "../tests/startup_bridge_test.cpp")
apply_standard_settings(fuzevpn_startup_bridge_test)
target_compile_features(fuzevpn_startup_bridge_test PRIVATE cxx_std_20)
target_compile_definitions(fuzevpn_startup_bridge_test PRIVATE
  "$<TARGET_PROPERTY:${BINARY_NAME},COMPILE_DEFINITIONS>")
target_include_directories(fuzevpn_startup_bridge_test PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}" "${CMAKE_SOURCE_DIR}")
target_link_libraries(fuzevpn_startup_bridge_test PRIVATE
  "$<TARGET_PROPERTY:${BINARY_NAME},LINK_LIBRARIES>")
set_target_properties(fuzevpn_startup_bridge_test PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")

if(FUZEVPN_ENABLE_OPENVPN3 AND TARGET fuzevpn_openvpn_core)
  add_executable(fuzevpn_openvpn_safety_test EXCLUDE_FROM_ALL
    "../tests/openvpn_safety_test.cpp")
  apply_standard_settings(fuzevpn_openvpn_safety_test)
  target_compile_features(fuzevpn_openvpn_safety_test PRIVATE cxx_std_20)
  target_compile_options(fuzevpn_openvpn_safety_test PRIVATE /utf-8)
  target_compile_definitions(fuzevpn_openvpn_safety_test PRIVATE
    NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0601 _CRT_SECURE_NO_WARNINGS)
  target_include_directories(fuzevpn_openvpn_safety_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}" "${FUZEVPN_OPENVPN3_CORE_DIR}"
    "${FUZEVPN_OPENVPN3_VCPKG_DIR}/include")
  target_link_libraries(fuzevpn_openvpn_safety_test PRIVATE ws2_32 iphlpapi)
  set_target_properties(fuzevpn_openvpn_safety_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
  add_test(NAME openvpn_safety COMMAND fuzevpn_openvpn_safety_test)
  set_tests_properties(openvpn_safety PROPERTIES TIMEOUT 45)

  add_executable(fuzevpn_network_runtime_test EXCLUDE_FROM_ALL
    "../tests/network_runtime_test.cpp")
  apply_standard_settings(fuzevpn_network_runtime_test)
  target_compile_definitions(fuzevpn_network_runtime_test PRIVATE NOMINMAX)
  target_include_directories(fuzevpn_network_runtime_test PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}" "${FUZEVPN_OPENVPN3_VCPKG_DIR}/include")
  target_link_libraries(fuzevpn_network_runtime_test PRIVATE
    ws2_32
    debug "${FUZEVPN_OPENVPN3_VCPKG_DIR}/debug/lib/libcrypto.lib"
    optimized "${FUZEVPN_OPENVPN3_VCPKG_DIR}/lib/libcrypto.lib")
  set_target_properties(fuzevpn_network_runtime_test PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/native-tests")
  add_custom_command(TARGET fuzevpn_network_runtime_test POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
      "$<IF:$<CONFIG:Debug>,${FUZEVPN_OPENVPN3_VCPKG_DIR}/debug/bin/${FUZEVPN_CRYPTO_DLL_NAME},${FUZEVPN_OPENVPN3_VCPKG_DIR}/bin/${FUZEVPN_CRYPTO_DLL_NAME}>"
      "$<TARGET_FILE_DIR:fuzevpn_network_runtime_test>/${FUZEVPN_CRYPTO_DLL_NAME}")
  add_test(NAME network_runtime COMMAND fuzevpn_network_runtime_test)
  set_tests_properties(network_runtime PROPERTIES TIMEOUT 30)
endif()
