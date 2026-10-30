# SPDX-License-Identifier: MPL-2.0
# Register each isolated executable once: CTest and the build aggregate share
# the same declaration, including tests excluded from the application build.
add_custom_target(fuzevpn_native_tests)

function(fuzevpn_add_native_test name target)
  if(NOT TARGET "${target}")
    message(FATAL_ERROR "Native test ${name} references missing target ${target}.")
  endif()
  get_target_property(target_type "${target}" TYPE)
  if(NOT target_type STREQUAL "EXECUTABLE")
    message(FATAL_ERROR "Native test ${name} must reference an executable target.")
  endif()
  add_test(NAME "${name}" COMMAND "${target}" ${ARGN})
  set_tests_properties("${name}" PROPERTIES
    FUZEVPN_NATIVE_REGISTERED TRUE FUZEVPN_NATIVE_TARGET "${target}")
  add_dependencies(fuzevpn_native_tests "${target}")
endfunction()

function(fuzevpn_add_native_script_test name script)
  if(NOT EXISTS "${script}")
    message(FATAL_ERROR "Native script test ${name} references missing file ${script}.")
  endif()
  find_program(FUZEVPN_TEST_POWERSHELL NAMES pwsh powershell REQUIRED)
  add_test(NAME "${name}" COMMAND "${FUZEVPN_TEST_POWERSHELL}"
    -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "${script}")
  set_tests_properties("${name}" PROPERTIES
    FUZEVPN_NATIVE_REGISTERED TRUE FUZEVPN_NATIVE_SCRIPT "${script}")
  set_property(TARGET fuzevpn_native_tests APPEND PROPERTY SOURCES "${script}")
endfunction()

function(fuzevpn_validate_native_test_registry)
  get_property(native_tests DIRECTORY PROPERTY TESTS)
  foreach(name IN LISTS native_tests)
    get_test_property("${name}" FUZEVPN_NATIVE_REGISTERED registered)
    if(NOT registered OR registered STREQUAL "NOTFOUND")
      message(FATAL_ERROR
        "Register native CTest ${name} through fuzevpn_add_native_test or fuzevpn_add_native_script_test.")
    endif()
  endforeach()
endfunction()
