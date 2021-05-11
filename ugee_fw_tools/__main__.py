# Copyright (C) 2021 Torge Matthies
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Author contact info:
#   E-Mail address: openglfreak@googlemail.com
#   PGP key fingerprint: 0535 3830 2F11 C888 9032 FAD2 7C95 CD70 C9E8 438D

import mmap
import os.path
import sys

import ugee_fw_tools.key as key
import ugee_fw_tools.sm4 as sm4

__all__ = ('main',)


def get_key(directory='.'):
    with open(os.path.join(directory, 'UgeeBootLoader.exe'), 'rb') as exefile, \
            mmap.mmap(exefile.fileno(), 0, access=mmap.ACCESS_READ) as mapping:
        return key.extract_key(mapping)


def transcrypt_file(file_path, output_path, sm4_key, decrypt=False):
    with open(file_path, 'rb') as infile, open(output_path, 'wb') as outfile:
        sm4.sm4_transcrypt(infile, sm4_key, decrypt, output_file=outfile)


def decode(directory='.', info=False, firmware=False):
    if not firmware and not info:
        return

    sm4_key = get_key(directory)
    if not sm4_key:
        raise RuntimeError('Failed extracting key from updater')

    if info:
        transcrypt_file(
            os.path.join(directory, 'Bootloader-tool.enc'),
            os.path.join(directory, 'Bootloader-tool.bin'),
            sm4_key,
            True
        )

    if firmware:
        with open(os.path.join(directory, 'Bootloader-tool.bin'), 'rb') as \
                infofile:
            infofile.seek(10)
            filename = infofile.read()
        filename = filename[:filename.find(b'\0')]
        filename = filename.decode()
        transcrypt_file(
            os.path.join(directory, 'bin', filename),
            os.path.join(directory, 'bin', filename.replace('enc', '')),
            sm4_key,
            True
        )


def encode(directory='.', info=False, firmware=False):
    if not firmware and not info:
        return

    sm4_key = get_key(directory)
    if not sm4_key:
        raise RuntimeError('Failed extracting key from updater')

    if info:
        transcrypt_file(
            os.path.join(directory, 'Bootloader-tool.bin'),
            os.path.join(directory, 'Bootloader-tool.enc'),
            sm4_key
        )

    if firmware:
        with open(os.path.join(directory, 'Bootloader-tool.bin'), 'rb') as \
                infofile:
            infofile.seek(10)
            filename = infofile.read()
        filename = filename[:filename.find(b'\0')]
        filename = filename.decode()
        transcrypt_file(
            os.path.join(directory, 'bin', filename.replace('enc', '')),
            os.path.join(directory, 'bin', filename),
            sm4_key
        )


def main(argv):
    if len(argv) != 2:
        print('Need encode or decode as the only parameter')
        return 1
    if argv[1] == 'decode':
        decode(info=True, firmware=True)
    elif argv[1] == 'encode':
        encode(info=True, firmware=True)
    else:
        print('Invalid verb: ' + argv[1], file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv) or 0)
