#!/bin/bash

rm -rf ./build CMakeUserPresets.json

conan install . -pr conan-debug -r conancenter -u --build=missing
conan install . -pr conan-release -r conancenter -u --build=missing

cmake --preset conan-debug
cmake --preset conan-release

