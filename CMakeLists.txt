cmake_minimum_required(VERSION 3.13...3.27)

set(PICO_BOARD pico_w)

# initialize the SDK based on PICO_SDK_PATH
# note: this must happen before project()
include(pico_sdk_import.cmake)

project(bachelor_thesis)

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

# clock glitching
add_executable(clock_glitching src/clock_glitching.c)
pico_generate_pio_header(clock_glitching ${CMAKE_CURRENT_LIST_DIR}/src/clock_spi.pio)
target_include_directories(clock_glitching PRIVATE include)
target_link_libraries(clock_glitching PRIVATE rpmc_ops pico_stdlib pico_mbedtls pico_cyw43_arch_none hardware_pio pico_multicore)
pico_enable_stdio_usb(clock_glitching 1)
pico_enable_stdio_uart(clock_glitching 0)
pico_add_extra_outputs(clock_glitching)
