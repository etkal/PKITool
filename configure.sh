#!/bin/bash

rm -rf ./build CMakeUserPresets.json

conan install . -r conancenter --build missing -s build_type=Debug
conan install . -r conancenter --build missing -s build_type=Release

cmake --preset conan-debug
cmake --preset conan-release

