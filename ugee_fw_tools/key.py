# Copyright (C) 2021 Torge Matthies
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Author contact info:
#   E-Mail address: openglfreak@googlemail.com
#   PGP key fingerprint: 0535 3830 2F11 C888 9032 FAD2 7C95 CD70 C9E8 438D

import re

import ugee_fw_tools.pe as pe

__all__ = ('extract_key',)

BASE_REGEX = b'\x0f\xb6(?:\x05|\x0d|\x15|\x1d|\x25|\x2d|\x35|\x3d)(?P<addr#>.{4})'

ADDRESS_REGEX = b'\x55\x8b\xec\x81\xec.{4}.*'
for __i in range(0, 16):
    ADDRESS_REGEX += BASE_REGEX.replace(b'#', str(__i).encode('utf-8'))
    ADDRESS_REGEX += b'.{0,32}'
ADDRESS_REGEX += b'\x8b.{5}\x33.{6}\x33.{6}\x33'
ADDRESS_REGEX = re.compile(ADDRESS_REGEX)


def find_key_address_in_exe(binary):
    for match in ADDRESS_REGEX.finditer(binary):
        addresses = []
        for i in range(0, 16):
            address = int.from_bytes(match.group('addr' + str(i)), 'little')
            addresses.append(address)
        addresses.sort()
        for i in range(1, 16):
            if addresses[i] != addresses[0] + i:
                break
        else:
            return addresses[0]
    return None


def extract_key(binary):
    address = find_key_address_in_exe(binary)
    if address is None:
        return None
    return pe.extract_data_from_exe(binary, address, 16)
