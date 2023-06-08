# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(hello_world)

if(DEFINED CONFIG_ROCKETZ_BOOTLOADER)
file(GLOB rocketz_src src/rocket-z/*.c src/rocket-z/pem/*.c)
else()
file(GLOB_RECURSE rocketz_src src/boot-info-ctrl.c src/boot-log.c)
endif()

target_sources(
app PRIVATE ${rocketz_src}
src/main.c
src/arm_cleanup.c
)
