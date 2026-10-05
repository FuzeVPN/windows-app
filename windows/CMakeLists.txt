# Project-level configuration.
cmake_minimum_required(VERSION 3.14)
project(fuzevpn_windows LANGUAGES C CXX)

string(TOLOWER "${CMAKE_GENERATOR_PLATFORM}" FUZEVPN_CMAKE_ARCH)
if(NOT FUZEVPN_CMAKE_ARCH)
  string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" FUZEVPN_CMAKE_ARCH)
endif()
if(FUZEVPN_CMAKE_ARCH STREQUAL "amd64" OR FUZEVPN_CMAKE_ARCH STREQUAL "x86_64")
  set(FUZEVPN_CMAKE_ARCH "x64")
endif()
set(FUZEVPN_TARGET_ARCH "${FUZEVPN_CMAKE_ARCH}" CACHE STRING "Native package architecture: x64 or arm64")
set_property(CACHE FUZEVPN_TARGET_ARCH PROPERTY STRINGS x64 arm64)
if(NOT FUZEVPN_TARGET_ARCH MATCHES "^(x64|arm64)$" OR
   NOT FUZEVPN_TARGET_ARCH STREQUAL FUZEVPN_CMAKE_ARCH)
  message(FATAL_ERROR "FUZEVPN_TARGET_ARCH must match the CMake native x64 or ARM64 target.")
endif()
if(FLUTTER_TARGET_PLATFORM AND NOT FLUTTER_TARGET_PLATFORM STREQUAL "windows-${FUZEVPN_TARGET_ARCH}")
  message(FATAL_ERROR "Flutter and native package architectures differ.")
endif()

# The name of the executable created for the application. Change this to change
# the on-disk name of your application.
set(BINARY_NAME "fuzevpn_windows")
set(FUZEVPN_SERVICE_TARGET "fuzevpn_service")

# Explicitly opt in to modern CMake behaviors to avoid warnings with recent
# versions of CMake.
cmake_policy(VERSION 3.14...3.25)

# Define build configuration option.
get_property(IS_MULTICONFIG GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
if(IS_MULTICONFIG)
  set(CMAKE_CONFIGURATION_TYPES "Debug;Profile;Release"
    CACHE STRING "" FORCE)
else()
  if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE "Debug" CACHE
      STRING "Flutter build mode" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
      "Debug" "Profile" "Release")
  endif()
endif()
# Define settings for the Profile build mode.
set(CMAKE_EXE_LINKER_FLAGS_PROFILE "${CMAKE_EXE_LINKER_FLAGS_RELEASE}")
set(CMAKE_SHARED_LINKER_FLAGS_PROFILE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE}")
set(CMAKE_C_FLAGS_PROFILE "${CMAKE_C_FLAGS_RELEASE}")
set(CMAKE_CXX_FLAGS_PROFILE "${CMAKE_CXX_FLAGS_RELEASE}")

# Use Unicode for all projects.
add_definitions(-DUNICODE -D_UNICODE)

# Compilation settings that should be applied to most targets.
#
# Be cautious about adding new options here, as plugins use this function by
# default. In most cases, you should add new options to specific targets instead
# of modifying this function.
function(APPLY_STANDARD_SETTINGS TARGET)
  target_compile_features(${TARGET} PUBLIC cxx_std_17)
  target_compile_options(${TARGET} PRIVATE /W4 /WX /wd"4100")
  target_compile_options(${TARGET} PRIVATE /EHsc)
  target_compile_definitions(${TARGET} PRIVATE "_HAS_EXCEPTIONS=0")
  target_compile_definitions(${TARGET} PRIVATE "$<$<CONFIG:Debug>:_DEBUG>")
endfunction()

# Flutter library and tool build rules.
set(FLUTTER_MANAGED_DIR "${CMAKE_CURRENT_SOURCE_DIR}/flutter")
add_subdirectory(${FLUTTER_MANAGED_DIR})

# Do not compile an interface with missing or stale translations. Use the Dart
# SDK already selected by Flutter; this check needs no package/network access.
get_directory_property(FUZEVPN_FLUTTER_ROOT DIRECTORY "${FLUTTER_MANAGED_DIR}"
  DEFINITION FLUTTER_ROOT)
add_custom_target(fuzevpn_localization_check
  COMMAND "${FUZEVPN_FLUTTER_ROOT}/bin/cache/dart-sdk/bin/dart.exe"
    "${CMAKE_CURRENT_SOURCE_DIR}/../tool/l10n/generate_catalogs.dart" --check
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/.."
  COMMENT "Checking complete application translations"
  VERBATIM)
add_dependencies(flutter_assemble fuzevpn_localization_check)

# Application build; see runner/CMakeLists.txt.
enable_testing()
add_subdirectory("runner")


# Generated plugin build rules, which manage building the plugins and adding
# them to the application.
include(flutter/generated_plugins.cmake)


# === Installation ===
# Support files are copied into place next to the executable, so that it can
# run in place. This is done instead of making a separate bundle (as on Linux)
# so that building and running from within Visual Studio will work.
set(BUILD_BUNDLE_DIR "$<TARGET_FILE_DIR:${BINARY_NAME}>")
# Make the "install" step default, as it's required to run.
set(CMAKE_VS_INCLUDE_INSTALL_TO_DEFAULT_BUILD 1)
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX "${BUILD_BUNDLE_DIR}" CACHE PATH "..." FORCE)
endif()

set(INSTALL_BUNDLE_DATA_DIR "${CMAKE_INSTALL_PREFIX}/data")
set(INSTALL_BUNDLE_LIB_DIR "${CMAKE_INSTALL_PREFIX}")

# Ship the compiler's redistributable runtime with both executables. A clean
# Windows 10/11 installation need not already have Visual C++ installed.
set(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS_SKIP TRUE)
include(InstallRequiredSystemLibraries)
# The ARM64 redistributable directory also contains an x64 compatibility DLL.
# Native ARM64 binaries use vcruntime140.dll and must not bundle that x64 image.
if(FUZEVPN_TARGET_ARCH STREQUAL "arm64")
  foreach(FUZEVPN_CRT IN LISTS CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS)
    get_filename_component(FUZEVPN_CRT_NAME "${FUZEVPN_CRT}" NAME)
    if(FUZEVPN_CRT_NAME STREQUAL "vcruntime140_1.dll")
      list(REMOVE_ITEM CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS "${FUZEVPN_CRT}")
    endif()
  endforeach()
endif()
set(FUZEVPN_REQUIRED_CRT_FILES msvcp140.dll vcruntime140.dll)
if(FUZEVPN_TARGET_ARCH STREQUAL "x64")
  list(APPEND FUZEVPN_REQUIRED_CRT_FILES vcruntime140_1.dll)
endif()
foreach(FUZEVPN_REQUIRED_CRT IN LISTS FUZEVPN_REQUIRED_CRT_FILES)
  set(FUZEVPN_CRT_FOUND FALSE)
  foreach(FUZEVPN_CRT IN LISTS CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS)
    get_filename_component(FUZEVPN_CRT_NAME "${FUZEVPN_CRT}" NAME)
    if(FUZEVPN_CRT_NAME STREQUAL FUZEVPN_REQUIRED_CRT AND EXISTS "${FUZEVPN_CRT}")
      set(FUZEVPN_CRT_FOUND TRUE)
    endif()
  endforeach()
  if(NOT FUZEVPN_CRT_FOUND)
    message(FATAL_ERROR "Missing local Visual C++ redistributable: ${FUZEVPN_REQUIRED_CRT}")
  endif()
endforeach()
install(PROGRAMS ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS}
  DESTINATION "${INSTALL_BUNDLE_LIB_DIR}" COMPONENT Runtime)

install(TARGETS ${BINARY_NAME} ${FUZEVPN_SERVICE_TARGET} fuzevpn_update fuzevpn_runtime
  RUNTIME DESTINATION "${CMAKE_INSTALL_PREFIX}"
  COMPONENT Runtime)

install(FILES "${FLUTTER_ICU_DATA_FILE}" DESTINATION "${INSTALL_BUNDLE_DATA_DIR}"
  COMPONENT Runtime)

install(FILES "${FLUTTER_LIBRARY}" DESTINATION "${INSTALL_BUNDLE_LIB_DIR}"
  COMPONENT Runtime)

if(PLUGIN_BUNDLED_LIBRARIES)
  install(FILES "${PLUGIN_BUNDLED_LIBRARIES}"
    DESTINATION "${INSTALL_BUNDLE_LIB_DIR}"
    COMPONENT Runtime)
endif()

# Copy the native assets provided by the build.dart from all packages.
set(NATIVE_ASSETS_DIR "${PROJECT_BUILD_DIR}native_assets/windows/")
install(DIRECTORY "${NATIVE_ASSETS_DIR}"
   DESTINATION "${INSTALL_BUNDLE_LIB_DIR}"
   COMPONENT Runtime)

# Fully re-copy the assets directory on each build to avoid having stale files
# from a previous install.
set(FLUTTER_ASSET_DIR_NAME "flutter_assets")
install(CODE "
  file(REMOVE_RECURSE \"${INSTALL_BUNDLE_DATA_DIR}/${FLUTTER_ASSET_DIR_NAME}\")
  " COMPONENT Runtime)
install(DIRECTORY "${PROJECT_BUILD_DIR}/${FLUTTER_ASSET_DIR_NAME}"
  DESTINATION "${INSTALL_BUNDLE_DATA_DIR}" COMPONENT Runtime)

# Install the AOT library on non-Debug builds only.
install(FILES "${AOT_LIBRARY}" DESTINATION "${INSTALL_BUNDLE_DATA_DIR}"
  CONFIGURATIONS Profile;Release
  COMPONENT Runtime)
