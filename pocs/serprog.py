import serial

class Serprog:
    def __init__(self, port: str, spi_speed: int, baudrate: int = 115200):
        assert spi_speed > 0
        assert baudrate > 0

        self.spi_connection = serial.Serial(port, baudrate=baudrate, timeout=0.1)

        self.spi_connection.write(b'\x14' + spi_speed.to_bytes(4, byteorder='little'))
        if self.spi_connection.read(1)[0] != 0x06:
            raise RuntimeError('Error: could not set spi speed')

        number = self.spi_connection.read(4)
        if len(number) <= 1 and number[0] == 0x15:
            raise RuntimeError('Error: could not set spi speed')
        #print(f'Serprog: Set spi speed of {int.from_bytes(number, byteorder='little')} Hz')

    def exchange(self, write_buf: bytes, read_amount: int, glitch_cycles: int | None = None) -> bytes:
        assert read_amount >= 0
        glitch_cycles_provided = glitch_cycles is not None

        msg = ((b'\x66' if glitch_cycles_provided else b'\x13')
               + len(write_buf).to_bytes(3, byteorder='little')
               + read_amount.to_bytes(3, byteorder='little')
               + (glitch_cycles.to_bytes(4, byteorder='little') if glitch_cycles_provided else b'')
               + write_buf)

        self.spi_connection.write(msg)

        if self.spi_connection.read(1)[0] != 0x06:
            raise RuntimeError('Error: device did not acknowledge transmission')

        content = self.spi_connection.read(read_amount)
        if len(content) < read_amount and content[0] == 0x15:
            raise RuntimeError('Error: did not the proper answer')
        return content


if __name__ == '__main__':
    print(Serprog('/dev/ttyACM0', 1_000_000).exchange(b'\x9f', 3))
