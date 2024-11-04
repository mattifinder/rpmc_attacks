cmake_minimum_required(VERSION 3.13...3.27)

set(PICO_BOARD pico_w)

# initialize the SDK based on PICO_SDK_PATH
# note: this must happen before project()
include(pico_sdk_import.cmake)

project(my_project)

# initialize the Raspberry Pi Pico SDK
pico_sdk_init()

# rest of your project
add_executable(overflow
    src/main.c
)

target_include_directories(overflow PRIVATE include)

# Add pico_stdlib library which aggregates commonly used features
target_link_libraries(overflow PRIVATE pico_stdlib pico_mbedtls hardware_spi pico_cyw43_arch_none)

pico_enable_stdio_usb(overflow 1)
pico_enable_stdio_uart(overflow 0)

# create map/bin/hex/uf2 file in addition to ELF.
pico_add_extra_outputs(overflow)

