# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(hello_world)

target_sources(app PRIVATE src/main.c src/rocket-z/controller.c src/rocket-z/bootloader.c
$ENV{ZEPHYR_BASE}/lib/os/json.c
$ENV{ZEPHYR_BASE}/lib/os/base64.c
$ENV{NCS_PATH_2_3}/modules/crypto/tinycrypt/lib/source/sha256.c
$ENV{NCS_PATH_2_3}/modules/crypto/tinycrypt/lib/source/ecc_dsa.c
$ENV{NCS_PATH_2_3}/modules/crypto/tinycrypt/lib/source/ecc.c
src/rocket-z/pem/tiny-asn1.c
src/rocket-z/pem/pem-decode.c
)
