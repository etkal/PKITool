@REM Windows configure script

rmdir /s/q .\build
del .\CMakeUserPresets.json

@REM conan install . -r conancenter --build missing -s build_type=Debug
@REM conan install . -r conancenter --build missing -s build_type=Release
conan install . -r conancenter -s build_type=Debug
conan install . -r conancenter -s build_type=Release

cmake --preset conan-default
