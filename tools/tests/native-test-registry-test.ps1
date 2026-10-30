# SPDX-License-Identifier: MPL-2.0
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSScriptRoot '../BuildSupport.psm1') -Force
$root = Get-FuzeProjectRoot
$tools = Get-FuzeVisualStudioTools -Architecture x64
$fixture = Join-Path $root ('build/native-test-registry-tests/' + [guid]::NewGuid().ToString('N'))
$good = Join-Path $fixture 'good'
$bad = Join-Path $fixture 'bad'
[void][IO.Directory]::CreateDirectory($good)
[void][IO.Directory]::CreateDirectory($bad)
$registry = (Join-Path $root 'windows/runner/native_test_registry.cmake').Replace('\','/')
$prefix = @"
cmake_minimum_required(VERSION 3.20)
project(NativeTestRegistryFixture LANGUAGES CXX)
enable_testing()
include("$registry")
"@
# Both executables are excluded from ALL: CTest only passes if the aggregate
# actually builds every registration and preserves its command arguments.
[IO.File]::WriteAllText((Join-Path $good 'test.cpp'), @'
#include <cstring>
int main(int argc, char** argv) {
  return argc == 2 && std::strcmp(argv[1], "fixture-argument") == 0 ? 0 : 1;
}
'@)
[IO.File]::WriteAllText((Join-Path $good 'manual.cpp'), '#error A manual probe must not be built by the test aggregate.')
[IO.File]::WriteAllText((Join-Path $good 'contract.ps1'), 'if ($args.Count) { throw "Unexpected arguments." }; exit 0')
[IO.File]::WriteAllText((Join-Path $good 'CMakeLists.txt'), $prefix + @'

add_executable(first EXCLUDE_FROM_ALL test.cpp)
add_executable(second EXCLUDE_FROM_ALL test.cpp)
add_executable(manual_probe EXCLUDE_FROM_ALL manual.cpp)
fuzevpn_add_native_test(first_case first fixture-argument)
fuzevpn_add_native_test(second_case second fixture-argument)
fuzevpn_add_native_script_test(script_case "${CMAKE_CURRENT_SOURCE_DIR}/contract.ps1")
fuzevpn_validate_native_test_registry()
'@)
$goodBuild = Join-Path $good 'build'
Invoke-FuzeChecked $tools.CMake @('-S',$good,'-B',$goodBuild,'-G','Visual Studio 18 2026','-A','x64')
Invoke-FuzeChecked $tools.CMake @('--build',$goodBuild,'--config','Release','--target','fuzevpn_native_tests','--parallel','2')
Invoke-FuzeChecked $tools.CTest @('--test-dir',$goodBuild,'-C','Release','--output-on-failure','--no-tests=error')
# A newly added raw CTest must fail configuration instead of silently escaping
# the aggregate and later running a missing or stale executable.
[IO.File]::WriteAllText((Join-Path $bad 'test.cpp'), 'int main() { return 0; }')
[IO.File]::WriteAllText((Join-Path $bad 'CMakeLists.txt'), $prefix + @'

add_executable(orphan EXCLUDE_FROM_ALL test.cpp)
add_test(NAME orphan_case COMMAND orphan)
fuzevpn_validate_native_test_registry()
'@)
# The rejection is expected: its stderr must not stop the script, and its exit
# code must not leak to a caller that checks $LASTEXITCODE afterwards.
$previousPreference = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
try {
  $rejected = @(& $tools.CMake -S $bad -B (Join-Path $bad 'build') -G 'Visual Studio 18 2026' -A x64 2>&1)
  $rejectedExitCode = $LASTEXITCODE
} finally {
  $ErrorActionPreference = $previousPreference
}
if ($rejectedExitCode -eq 0 -or ($rejected -join "`n") -notmatch 'Register native CTest orphan_case through fuzevpn_add_native_test') {
  throw 'An unregistered CTest executable must fail configuration with an actionable error.'
}
$global:LASTEXITCODE = 0
Write-Host 'Native test registry passed: a fresh aggregate builds every executable fixture, preserves arguments, runs script contracts, excludes manual probes and rejects orphan CTests.'
