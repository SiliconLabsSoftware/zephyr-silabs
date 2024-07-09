# Copyright (c) 2023 Antmicro
#
# SPDX-License-Identifier: Apache-2.0

#!/usr/bin/env python3

import sys
import crc as crc_mod
import argparse
import struct
from typing import Union
import intelhex

crc_cfg = crc_mod.Configuration(
    width=32,
    polynomial=0xd95eaae5,
    init_value=0,
    final_xor_value=0,
    reverse_input=True,
    reverse_output=True
)


def calc_checksum(data: Union[bytes, bytearray], size: int, prev_sum: int) -> int:
    # Truncate
    data = data[:size]
    # Zero-pad data to mul of 4 bytes
    nzeros = ((len(data) + 3) // 4 * 4) - len(data)
    data += b'\0' * nzeros
    # Reinterpret data as LE u32
    ints = list(x[0] for x in struct.iter_unpack('<I', data))
    # Sum
    chk = prev_sum + sum(ints)
    # Convert to u32 and account each overflow as 1's complement addition
    chk = (chk & 0xFFffFFff) + (chk >> 32)
    chk = (~chk) & 0xFFffFFff
    return chk


def calc_crc32(data: bytes) -> int:
    calc = crc_mod.Calculator(crc_cfg, optimized=True)
    return calc.checksum(data)


def set_bits(x: int, off: int, size: int, field: int) -> int:
    field = int(field)
    mask = ((1 << size) - 1) << off
    x &= ~mask
    x |= (field << off) & mask
    return x


def get_bootload_entry(ctrl_len: int = 0, ctrl_reserved: int = 0,
                       ctrl_spi_32bitmode: bool = False,
                       ctrl_release_ta_softreset: bool = False,
                       ctrl_start_from_rom_pc: bool = False,
                       ctrl_spi_8bitmode: bool = False,
                       ctrl_last_entry: bool = True,
                       dest_addr: int = 0) -> bytes:
    # Format bootload_entry struct
    ctrl = 0
    ctrl = set_bits(ctrl, 0, 24, ctrl_len)
    ctrl = set_bits(ctrl, 24, 3, ctrl_reserved)
    ctrl = set_bits(ctrl, 27, 1, ctrl_spi_32bitmode)
    ctrl = set_bits(ctrl, 28, 1, ctrl_release_ta_softreset)
    ctrl = set_bits(ctrl, 29, 1, ctrl_start_from_rom_pc)
    ctrl = set_bits(ctrl, 30, 1, ctrl_spi_8bitmode)
    ctrl = set_bits(ctrl, 31, 1, ctrl_last_entry)
    return struct.pack('<II', ctrl, dest_addr)


def get_bootload_ds(offset: int, ivt_offset: int, fixed_pattern: int = 0x5aa5) -> bytes:
    ret = b''
    ret += int(fixed_pattern).to_bytes(2, 'little')
    ret += int(offset).to_bytes(2, 'little')
    ret += int(ivt_offset).to_bytes(4, 'little')
    for i in range(7):
        ret += get_bootload_entry(ctrl_last_entry=i==0)
    return ret


def get_fwupreq(flash_location: int, image_size: int) -> bytes:
    # Field values
    cflags = 1
    sha_type = 0
    magic_no = 0x900d900d
    fw_version = 0
    # Initially CRC value is set to 0, then the CRC is calculated on the
    # whole image (including fwupreq header), and injected here
    crc = 0
    mic = [0, 0, 0, 0]
    counter = 0
    rsvd = [0, 0, 0, 0, magic_no]
    # Format
    ret = b''
    ret += cflags.to_bytes(2, 'little')
    ret += sha_type.to_bytes(2, 'little')
    ret += magic_no.to_bytes(4, 'little')
    ret += image_size.to_bytes(4, 'little')
    ret += fw_version.to_bytes(4, 'little')
    ret += flash_location.to_bytes(4, 'little')
    ret += crc.to_bytes(4, 'little')
    for x in mic:
        ret += x.to_bytes(4, 'little')
    ret += counter.to_bytes(4, 'little')
    for x in rsvd:
        ret += x.to_bytes(4, 'little')
    return ret


def main():
    parser = argparse.ArgumentParser(
        description='Converts ROM binary into an ISP binary for SiLabs SiWx917 SoCs',
        allow_abbrev=False
    )
    parser.add_argument(
        'ifile',
        metavar='INPUT.BIN',
        help='ROM binary file to read',
        type=str
    )
    parser.add_argument(
        'ofile',
        metavar='OUTPUT.BIN',
        help='ISP binary file to write',
        type=str
    )
    parser.add_argument(
        '--rom_addr',
        metavar='ADDRESS',
        help='Address at which FW image begins in the SoC (this understands hex if prefixed with 0x)',
        type=str,
        required=True
    )
    parser.add_argument(
        '--out_hex',
        metavar='FILE.HEX',
        help='Generate Intel HEX output in addition to binary one',
        type=str,
    )
    args = parser.parse_args()

    rom_addr = int(args.rom_addr, 0)
    ifile = args.ifile
    ofile = args.ofile
    out_hex = args.out_hex

    # Read ROM binary
    with open(ifile, 'rb') as f:
        img = bytearray(f.read())

    # Compute checksum
    chk = calc_checksum(img, 236, 1)
    print(f'ROM checksum: 0x{chk:08x}', file=sys.stderr)
    # Inject checksum into the image
    img[236:(236+4)] = chk.to_bytes(4, 'little')


    bl = get_bootload_ds(4032, rom_addr)

    # Zero-pad to 4032 bytes and glue to ROM
    bl += b'\0' * (4032 - len(bl))
    img = bl + img

    # Get fwupreq header and glue it to the bootloader payload
    fwupreq = get_fwupreq(rom_addr - 0x8001000, len(img))
    img = bytearray(fwupreq + img)
    # Calculate and inject CRC
    crc = calc_crc32(img)
    print(f'Image CRC: 0x{crc:08x}', file=sys.stderr)
    img[20:24] = crc.to_bytes(4, 'little')

    # Write ISP binary
    with open(ofile, 'wb') as f:
        f.write(img)

    # Calculate address at which this image should be placed in SoC
    # memory and produce Intel HEX if needed
    offset = rom_addr - 4096
    if out_hex:
        hx = intelhex.IntelHex()
        hx.frombytes(img, offset)
        hx.write_hex_file(out_hex, byte_count=32)


    print('Done.', file=sys.stderr)


if __name__ == '__main__':
    main()
