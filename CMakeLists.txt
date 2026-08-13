cmake_minimum_required(VERSION 3.13...3.27)

set(PICO_BOARD pico2_w)
set(CMAKE_C_STANDARD 23)
set(COMMON_COMPILE_OPTIONS -Wall -Wextra)
set(PICO_USE_FASTEST_SUPPORTED_CLOCK 1)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# initialize the SDK based on PICO_SDK_PATH
# note: this must happen before project()
include(pico_sdk_import.cmake)

project(rpmc_glitch_setup)

# initialize the Raspberry Pi Pico SDK
pico_sdk_init()

# rpmc_ops library
add_library(rpmc_ops src/rpmc_ops.c)
target_include_directories(rpmc_ops PRIVATE include)
target_link_libraries(rpmc_ops PUBLIC pico_stdlib)
target_link_libraries(rpmc_ops PRIVATE pico_mbedtls)

# overflow
add_executable(overflow src/overflow.c)
target_include_directories(overflow PRIVATE include)
target_link_libraries(overflow PRIVATE rpmc_ops pico_stdlib pico_mbedtls pico_cyw43_arch_none hardware_spi)
pico_enable_stdio_usb(overflow 1)
pico_enable_stdio_uart(overflow 0)
pico_add_extra_outputs(overflow)

# serprog_glitch
add_executable(serprog_glitch src/serprog_with_glitch.c)
target_include_directories(serprog_glitch PRIVATE include)
target_link_libraries(serprog_glitch PRIVATE pico_stdlib hardware_spi pico_multicore)
pico_enable_stdio_usb(serprog_glitch 1)
pico_enable_stdio_uart(serprog_glitch 0)
pico_add_extra_outputs(serprog_glitch)
target_compile_definitions(serprog_glitch PRIVATE PROGRAM_MODE_FIXED_DELAY)

# glitch_finder
add_executable(glitch_finder src/serprog_with_glitch.c)
target_include_directories(glitch_finder PRIVATE include)
target_link_libraries(glitch_finder PRIVATE pico_stdlib hardware_spi pico_multicore)
pico_enable_stdio_usb(glitch_finder 1)
pico_enable_stdio_uart(glitch_finder 0)
pico_add_extra_outputs(glitch_finder)
target_compile_definitions(glitch_finder PRIVATE PROGRAM_MODE_FIND_DELAY)

# interposer
add_executable(interposer src/interposer.c)
target_include_directories(interposer PRIVATE include)
target_link_libraries(interposer PRIVATE pico_stdlib hardware_pio hardware_clocks pico_multicore pico_mbedtls)
pico_generate_pio_header(interposer ${CMAKE_CURRENT_LIST_DIR}/src/spi_sniff.pio ${CMAKE_CURRENT_LIST_DIR}/src/rpmc_sniffer.pio)
pico_enable_stdio_usb(interposer 1)
pico_enable_stdio_uart(interposer 0)