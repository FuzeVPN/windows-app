# SPDX-License-Identifier: MPL-2.0
# Executed after linking, using the exact local source tree used by the build.
if(NOT DEFINED SOURCE_ROOT OR NOT DEFINED BUNDLE_DIR)
  message(FATAL_ERROR "SOURCE_ROOT and BUNDLE_DIR are required")
endif()
set(CORE "${SOURCE_ROOT}/third_party/openvpn3-core")
set(WIREGUARD "${SOURCE_ROOT}/third_party/wireguard/1.1")
set(DCO "${SOURCE_ROOT}/third_party/openvpn-dco/2.8.7")
set(LICENSE_DIR "${BUNDLE_DIR}/licenses")
file(MAKE_DIRECTORY "${LICENSE_DIR}")
configure_file("${SOURCE_ROOT}/third_party/miniz/LICENSE"
  "${LICENSE_DIR}/miniz-LICENSE.txt" COPYONLY)
configure_file("${SOURCE_ROOT}/third_party/tray_manager/LICENSE"
  "${LICENSE_DIR}/tray_manager-LICENSE.txt" COPYONLY)
configure_file("${SOURCE_ROOT}/third_party/tray_manager/FUZEVPN-PATCHES.md"
  "${LICENSE_DIR}/tray_manager-local-changes.md" COPYONLY)
configure_file("${SOURCE_ROOT}/THIRD_PARTY_NOTICES.md"
  "${BUNDLE_DIR}/THIRD_PARTY_NOTICES.md" COPYONLY)
configure_file("${WIREGUARD}/NOTICE.md"
  "${LICENSE_DIR}/WireGuard-NOTICE.md" COPYONLY)
configure_file("${WIREGUARD}/NOTICE.md"
  "${BUNDLE_DIR}/WIREGUARD_NOTICE.md" COPYONLY)
configure_file("${WIREGUARD}/LICENSE-WireGuardNT.txt"
  "${LICENSE_DIR}/WireGuardNT-LICENSE.txt" COPYONLY)
configure_file("${WIREGUARD}/LICENSE-WireGuardWindows.txt"
  "${LICENSE_DIR}/WireGuardWindows-LICENSE.txt" COPYONLY)
configure_file("${WIREGUARD}/wireguard-windows-1.1.1-source.zip"
  "${LICENSE_DIR}/wireguard-windows-1.1.1-source.zip" COPYONLY)
if(OPENVPN_ENABLED)
  # The runner passes the exact prefix selected for its target architecture.
  # Keep x64 as the fallback for standalone invocations of this helper.
  if(NOT DEFINED OPENVPN_VCPKG_DIR OR OPENVPN_VCPKG_DIR STREQUAL "")
    set(OPENVPN_VCPKG_DIR "${CORE}/vcpkg_installed/x64-windows")
  endif()
  file(MAKE_DIRECTORY "${BUNDLE_DIR}/openvpn-dco")
  configure_file("${DCO}/NOTICE.md"
    "${BUNDLE_DIR}/openvpn-dco/NOTICE.md" COPYONLY)
  configure_file("${DCO}/LICENSE.txt"
    "${BUNDLE_DIR}/openvpn-dco/LICENSE.txt" COPYONLY)
  configure_file("${DCO}/source-2.8.7.zip"
    "${BUNDLE_DIR}/openvpn-dco/source-2.8.7.zip" COPYONLY)
  configure_file("${CORE}/LICENSES/MPL-2.0.txt"
    "${LICENSE_DIR}/OpenVPN3-MPL-2.0.txt" COPYONLY)
  configure_file("${CORE}/FUZEVPN-PINNED-VERSION.txt"
    "${LICENSE_DIR}/OpenVPN3-version.txt" COPYONLY)
  foreach(COMPONENT asio fmt jsoncpp lz4 openssl xxhash tap-windows6)
    configure_file("${OPENVPN_VCPKG_DIR}/share/${COMPONENT}/copyright"
      "${LICENSE_DIR}/${COMPONENT}-copyright.txt" COPYONLY)
  endforeach()
  # Do not include the prebuilt vcpkg tree. Include every local Core source,
  # build recipe and license, including local changes, without downloading.
  file(GLOB CORE_ENTRIES RELATIVE "${CORE}" "${CORE}/*" "${CORE}/.clang-format"
    "${CORE}/.gitattributes" "${CORE}/.gitignore")
  list(REMOVE_ITEM CORE_ENTRIES "vcpkg_installed" ".git")
  execute_process(
    COMMAND "${CMAKE_COMMAND}" -E tar cf
      "${LICENSE_DIR}/OpenVPN3-corresponding-source.zip" --format=zip --
      ${CORE_ENTRIES}
    WORKING_DIRECTORY "${CORE}"
    RESULT_VARIABLE ARCHIVE_RESULT)
  if(NOT ARCHIVE_RESULT EQUAL 0)
    message(FATAL_ERROR "Could not package the corresponding OpenVPN3 source")
  endif()
endif()
