# Copyright (C) 2021 Torge Matthies
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# Author contact info:
#   E-Mail address: openglfreak@googlemail.com
#   PGP key fingerprint: 0535 3830 2F11 C888 9032 FAD2 7C95 CD70 C9E8 438D

import subprocess

__all__ = ('sm4_transcrypt',)


def _sm4_transcrypt_to_string(cmd, kwargs):  # type: (list, dict) -> bytes
    proc = subprocess.run(cmd, **kwargs, capture_output=True, check=False)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode('utf-8'))
    return proc.stdout


def _sm4_transcrypt_to_file(cmd, kwargs, file):
    proc = subprocess.run(cmd, **kwargs, stdout=file, stderr=subprocess.PIPE, \
            check=False)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode('utf-8'))


def _sm4_transcrypt_input(cmd, input_data, output_file):
    if isinstance(input_data, str):
        input_data = input_data.encode()

    if hasattr(input_data, 'read'):
        kwargs = {'stdin': input_data}
    else:
        kwargs = {'input': input_data}

    if output_file is not None:
        return _sm4_transcrypt_to_file(cmd, kwargs, output_file)
    return _sm4_transcrypt_to_string(cmd, kwargs)


def sm4_transcrypt(input_data, key, decrypt=False, *, output_file=None):
    if isinstance(key, str):
        key = key.encode()

    if decrypt:
        mode_arg = '-d'
    else:
        mode_arg = '-e'
    cmd = ('openssl', 'enc', mode_arg, '-SM4-ECB', '-nopad', '-K', key.hex())

    return _sm4_transcrypt_input(cmd, input_data, output_file)
