cmake_minimum_required(VERSION 3.13...3.27)

set(PICO_BOARD pico_w)

# initialize the SDK based on PICO_SDK_PATH
# note: this must happen before project()
include(pico_sdk_import.cmake)

project(bachelor_thesis)

# initialize the Raspberry Pi Pico SDK
pico_sdk_init()

# overflow
add_executable(overflow src/overflow.c)
target_include_directories(overflow PRIVATE include)
target_link_libraries(overflow PRIVATE pico_stdlib pico_mbedtls hardware_spi pico_cyw43_arch_none)
pico_enable_stdio_usb(overflow 1)
pico_enable_stdio_uart(overflow 0)
pico_add_extra_outputs(overflow)

# clock glitching

