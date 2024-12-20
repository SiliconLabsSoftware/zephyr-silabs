#!/usr/bin/env python3

# Copyright (c) 2023 Antmicro
#
# SPDX-License-Identifier: Apache-2.0

import sys
import argparse
import struct
from typing import Union
import intelhex

# For reference:
#     width=32 poly=0xd95eaae5 init=0 refin=true refout=true xorout=0
# crc_table = [ 0 ] * 256
# def create_table():
#     for b in range(256):
#         register = b
#         for _ in range(8):
#             lsb = register & 1;
#             register >>= 1
#             if lsb:
#                 # Reflected polynomial: 0xd95eaae5
#                 register ^= 0xa7557a9b
#         crc_table[b] = register

crc_table = [
    0x00000000, 0x2073f610, 0x40e7ec20, 0x60941a30, 0x81cfd840, 0xa1bc2e50, 0xc1283460, 0xe15bc270,
    0x4d3545b7, 0x6d46b3a7, 0x0dd2a997, 0x2da15f87, 0xccfa9df7, 0xec896be7, 0x8c1d71d7, 0xac6e87c7,
    0x9a6a8b6e, 0xba197d7e, 0xda8d674e, 0xfafe915e, 0x1ba5532e, 0x3bd6a53e, 0x5b42bf0e, 0x7b31491e,
    0xd75fced9, 0xf72c38c9, 0x97b822f9, 0xb7cbd4e9, 0x56901699, 0x76e3e089, 0x1677fab9, 0x36040ca9,
    0x7a7fe3eb, 0x5a0c15fb, 0x3a980fcb, 0x1aebf9db, 0xfbb03bab, 0xdbc3cdbb, 0xbb57d78b, 0x9b24219b,
    0x374aa65c, 0x1739504c, 0x77ad4a7c, 0x57debc6c, 0xb6857e1c, 0x96f6880c, 0xf662923c, 0xd611642c,
    0xe0156885, 0xc0669e95, 0xa0f284a5, 0x808172b5, 0x61dab0c5, 0x41a946d5, 0x213d5ce5, 0x014eaaf5,
    0xad202d32, 0x8d53db22, 0xedc7c112, 0xcdb43702, 0x2ceff572, 0x0c9c0362, 0x6c081952, 0x4c7bef42,
    0xf4ffc7d6, 0xd48c31c6, 0xb4182bf6, 0x946bdde6, 0x75301f96, 0x5543e986, 0x35d7f3b6, 0x15a405a6,
    0xb9ca8261, 0x99b97471, 0xf92d6e41, 0xd95e9851, 0x38055a21, 0x1876ac31, 0x78e2b601, 0x58914011,
    0x6e954cb8, 0x4ee6baa8, 0x2e72a098, 0x0e015688, 0xef5a94f8, 0xcf2962e8, 0xafbd78d8, 0x8fce8ec8,
    0x23a0090f, 0x03d3ff1f, 0x6347e52f, 0x4334133f, 0xa26fd14f, 0x821c275f, 0xe2883d6f, 0xc2fbcb7f,
    0x8e80243d, 0xaef3d22d, 0xce67c81d, 0xee143e0d, 0x0f4ffc7d, 0x2f3c0a6d, 0x4fa8105d, 0x6fdbe64d,
    0xc3b5618a, 0xe3c6979a, 0x83528daa, 0xa3217bba, 0x427ab9ca, 0x62094fda, 0x029d55ea, 0x22eea3fa,
    0x14eaaf53, 0x34995943, 0x540d4373, 0x747eb563, 0x95257713, 0xb5568103, 0xd5c29b33, 0xf5b16d23,
    0x59dfeae4, 0x79ac1cf4, 0x193806c4, 0x394bf0d4, 0xd81032a4, 0xf863c4b4, 0x98f7de84, 0xb8842894,
    0xa7557a9b, 0x87268c8b, 0xe7b296bb, 0xc7c160ab, 0x269aa2db, 0x06e954cb, 0x667d4efb, 0x460eb8eb,
    0xea603f2c, 0xca13c93c, 0xaa87d30c, 0x8af4251c, 0x6bafe76c, 0x4bdc117c, 0x2b480b4c, 0x0b3bfd5c,
    0x3d3ff1f5, 0x1d4c07e5, 0x7dd81dd5, 0x5dabebc5, 0xbcf029b5, 0x9c83dfa5, 0xfc17c595, 0xdc643385,
    0x700ab442, 0x50794252, 0x30ed5862, 0x109eae72, 0xf1c56c02, 0xd1b69a12, 0xb1228022, 0x91517632,
    0xdd2a9970, 0xfd596f60, 0x9dcd7550, 0xbdbe8340, 0x5ce54130, 0x7c96b720, 0x1c02ad10, 0x3c715b00,
    0x901fdcc7, 0xb06c2ad7, 0xd0f830e7, 0xf08bc6f7, 0x11d00487, 0x31a3f297, 0x5137e8a7, 0x71441eb7,
    0x4740121e, 0x6733e40e, 0x07a7fe3e, 0x27d4082e, 0xc68fca5e, 0xe6fc3c4e, 0x8668267e, 0xa61bd06e,
    0x0a7557a9, 0x2a06a1b9, 0x4a92bb89, 0x6ae14d99, 0x8bba8fe9, 0xabc979f9, 0xcb5d63c9, 0xeb2e95d9,
    0x53aabd4d, 0x73d94b5d, 0x134d516d, 0x333ea77d, 0xd265650d, 0xf216931d, 0x9282892d, 0xb2f17f3d,
    0x1e9ff8fa, 0x3eec0eea, 0x5e7814da, 0x7e0be2ca, 0x9f5020ba, 0xbf23d6aa, 0xdfb7cc9a, 0xffc43a8a,
    0xc9c03623, 0xe9b3c033, 0x8927da03, 0xa9542c13, 0x480fee63, 0x687c1873, 0x08e80243, 0x289bf453,
    0x84f57394, 0xa4868584, 0xc4129fb4, 0xe46169a4, 0x053aabd4, 0x25495dc4, 0x45dd47f4, 0x65aeb1e4,
    0x29d55ea6, 0x09a6a8b6, 0x6932b286, 0x49414496, 0xa81a86e6, 0x886970f6, 0xe8fd6ac6, 0xc88e9cd6,
    0x64e01b11, 0x4493ed01, 0x2407f731, 0x04740121, 0xe52fc351, 0xc55c3541, 0xa5c82f71, 0x85bbd961,
    0xb3bfd5c8, 0x93cc23d8, 0xf35839e8, 0xd32bcff8, 0x32700d88, 0x1203fb98, 0x7297e1a8, 0x52e417b8,
    0xfe8a907f, 0xdef9666f, 0xbe6d7c5f, 0x9e1e8a4f, 0x7f45483f, 0x5f36be2f, 0x3fa2a41f, 0x1fd1520f,
]


def calc_crc32(data: bytes) -> int:
    register = 0
    for b in data:
        register = crc_table[(b ^ register) & 0xFF] ^ (register >> 8)
    return register


def calc_checksum(data: Union[bytes, bytearray], size: int, prev_sum: int) -> int:
    # Truncate
    data = data[:size]
    # Zero-pad data to mul of 4 bytes
    nzeros = ((len(data) + 3) // 4 * 4) - len(data)
    data += b"\0" * nzeros
    # Reinterpret data as LE u32
    ints = list(x[0] for x in struct.iter_unpack("<I", data))
    # Sum
    chk = prev_sum + sum(ints)
    # Convert to u32 and account each overflow as 1"s complement addition
    chk = (chk & 0xFFFFFFFF) + (chk >> 32)
    chk = (~chk) & 0xFFFFFFFF
    return chk


def set_bits(x: int, off: int, size: int, field: int) -> int:
    field = int(field)
    mask = ((1 << size) - 1) << off
    x &= ~mask
    x |= (field << off) & mask
    return x


def get_bootload_entry(
        ctrl_len: int = 0,
        ctrl_reserved: int = 0,
        ctrl_spi_32bitmode: bool = False,
        ctrl_release_ta_softreset: bool = False,
        ctrl_start_from_rom_pc: bool = False,
        ctrl_spi_8bitmode: bool = False,
        ctrl_last_entry: bool = True,
        dest_addr: int = 0
) -> bytes:
    # Format bootload_entry struct
    ctrl = 0
    ctrl = set_bits(ctrl, 0, 24, ctrl_len)
    ctrl = set_bits(ctrl, 24, 3, ctrl_reserved)
    ctrl = set_bits(ctrl, 27, 1, ctrl_spi_32bitmode)
    ctrl = set_bits(ctrl, 28, 1, ctrl_release_ta_softreset)
    ctrl = set_bits(ctrl, 29, 1, ctrl_start_from_rom_pc)
    ctrl = set_bits(ctrl, 30, 1, ctrl_spi_8bitmode)
    ctrl = set_bits(ctrl, 31, 1, ctrl_last_entry)
    return struct.pack("<II", ctrl, dest_addr)


def get_bootload_ds(offset: int, ivt_offset: int, fixed_pattern: int = 0x5AA5) -> bytes:
    ret = b""
    ret += int(fixed_pattern).to_bytes(2, "little")
    ret += int(offset).to_bytes(2, "little")
    ret += int(ivt_offset).to_bytes(4, "little")
    for i in range(7):
        ret += get_bootload_entry(ctrl_last_entry=i == 0)
    return ret


def get_fwupreq(flash_location: int, image_size: int) -> bytes:
    # Field values
    cflags = 1
    sha_type = 0
    magic_no = 0x900D900D
    fw_version = 0
    # Initially CRC value is set to 0, then the CRC is calculated on the
    # whole image (including fwupreq header), and injected here
    crc = 0
    mic = [0, 0, 0, 0]
    counter = 0
    rsvd = [0, 0, 0, 0, magic_no]
    # Format
    ret = b""
    ret += cflags.to_bytes(2, "little")
    ret += sha_type.to_bytes(2, "little")
    ret += magic_no.to_bytes(4, "little")
    ret += image_size.to_bytes(4, "little")
    ret += fw_version.to_bytes(4, "little")
    ret += flash_location.to_bytes(4, "little")
    ret += crc.to_bytes(4, "little")
    for x in mic:
        ret += x.to_bytes(4, "little")
    ret += counter.to_bytes(4, "little")
    for x in rsvd:
        ret += x.to_bytes(4, "little")
    return ret


def main():
    parser = argparse.ArgumentParser(
        description="Converts raw binary output from Zephyr into an ISP binary for Silabs SiWx917 SoCs",
        allow_abbrev=False,
    )
    parser.add_argument(
        "ifile",
        metavar="INPUT.BIN",
        help="Raw binary file to read",
        type=argparse.FileType("rb"),
    )
    parser.add_argument(
        "ofile",
        metavar="OUTPUT.BIN",
        help="ISP binary file to write",
        type=argparse.FileType("wb"),
    )
    parser.add_argument(
        "--load-addr",
        metavar="ADDRESS",
        help="Address at which the raw binary image begins in the memory",
        type=lambda x: int(x, 0),
        required=True,
    )
    parser.add_argument(
        "--out-hex",
        metavar="FILE.HEX",
        help="Generate Intel HEX output in addition to binary one",
        type=argparse.FileType("w", encoding="ascii"),
    )
    args = parser.parse_args()

    img = bytearray(args.ifile.read())

    # Calculate and inject checksum
    chk = calc_checksum(img, 236, 1)
    print(f"ROM checksum: 0x{chk:08x}", file=sys.stderr)
    img[236:240] = chk.to_bytes(4, "little")

    # Get bootloader header, pad to 4032 and glue it to the image payload
    bl = bytearray(get_bootload_ds(4032, args.load_addr))
    padding = bytearray(4032 - len(bl))
    img = bl + padding + img

    # Get fwupreq header and glue it to the bootloader payload
    fwupreq = bytearray(get_fwupreq(args.load_addr - 0x8001000, len(img)))
    img = fwupreq + img

    # Calculate and inject CRC
    crc = calc_crc32(img)
    print(f"Image CRC: 0x{crc:08x}", file=sys.stderr)
    img[20:24] = crc.to_bytes(4, "little")

    args.ofile.write(img)

    # If you want to compare this file with the .hex file generated by Zephyr,
    # You have to reformat the Zephyr output:
    #   import intelhex
    #   hx = intelhex.IntelHex()
    #   hx.fromfile("zephyr.hex", "hex")
    #   hx.write_hex_file("zephyr.out.hex", byte_count=32)
    if args.out_hex:
        hx = intelhex.IntelHex()
        # len(bl) + len(padding) + len(fwupreq) == 4096
        hx.frombytes(img, args.load_addr - 4096)
        hx.write_hex_file(args.out_hex, byte_count=32)


if __name__ == "__main__":
    main()
