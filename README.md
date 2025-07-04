# RPMC glitch setup

This repository contains code useful for attacking RPMC-capable SPI flash chips.

It enables the use of different glitches on a target flash chip, mainly the overflow of a counter and some voltage glitching attacks.

Projects are tested on the **pico W**.

## Subprojects

### overflow:

This project is used to increment a counter to a value of UINT32_MAX *hopefully* allowing for a later wrap back to 0.
Alternatively `pocs/counter_overflow.py` can be use as well. 

### serprog_glitch:

This project allows for quicker voltage glitching iteration by receiving the delay used in the voltage glitch via serial.
It is meant to be used in conjuctions with some of the scripts found in the `pocs` directory.

## Building

```sh
mkdir build
cd build
cmake -DPICO_BOARD=pico_w ..
make
```
