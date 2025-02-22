# RPMC glitch setup

This repository contains all the pico code used in may bachelor's thesis.

It enables the use of different glitches on a target flash chip.

Projects are tested on the pico W.

## Subprojects

### overflow:

This project is used to increment a counter to a value of UINT32_MAX *hopefully* allowing for a subsequent wrap back to 0.

### clock_glitching:

This project uses pio state machines to quickly transmit one bit of spi data up to 4 times the normal speed.

### voltage_glitching:

This project allows for pulling a glitch line up after a specified amount of time.

### serprog_glitch:

This project allows for quicker voltage glitching iteration by receiving the delay used in the voltage glitch via serial.

## Building

```sh
mkdir build
cd build
cmake -DPICO_BOARD=pico_w ..
make
```
