@echo off
setlocal

:: Create build directory
if not exist "build" mkdir build
cd build

:: Configure CMake
cmake -G "Visual Studio 17 2022" -A x64 ..

:: Build
cmake --build . --config Release

:: Create runtime directory
if not exist "..\runtimes\win-x64\native" mkdir "..\runtimes\win-x64\native"

:: Copy DLL
copy /Y "Release\lwip_native.dll" "..\runtimes\win-x64\native\"

cd .. 