__all__ = ('extract_data_from_exe',)


def _decode_pe_int(data):
    return int.from_bytes(data, byteorder='little')


# pylint: disable=too-many-locals
def extract_data_from_exe(binary, virtual_address, length):
    if binary[0:2] != b'MZ':
        raise ValueError('Missing MZ magic number')

    pe_offset = _decode_pe_int(binary[0x3c:0x40])
    if binary[pe_offset:pe_offset + 4] != b'PE\0\0':
        raise ValueError('Missing PE magic number')

    section_count = _decode_pe_int(binary[pe_offset + 6:pe_offset + 8])
    opt_header_size = _decode_pe_int(binary[pe_offset + 20:pe_offset + 22])
    opt_header_offset = pe_offset + 24

    if opt_header_size < 2:
        raise ValueError('Missing PE optional header')
    opt_header_magic = _decode_pe_int(
        binary[opt_header_offset:opt_header_offset + 2]
    )
    if opt_header_magic not in (0x10b, 0x20b):
        raise ValueError('Unsupported PE optional magic')
    is_pe_plus = opt_header_magic == 0x20b

    image_base_offset = opt_header_offset + (24 if is_pe_plus else 28)
    image_base_size = 8 if is_pe_plus else 4
    if image_base_offset + 4 > opt_header_offset + opt_header_size:
        raise ValueError('Missing image base field')
    image_base = _decode_pe_int(
        binary[image_base_offset:image_base_offset + image_base_size]
    )

    sections_offset = opt_header_offset + opt_header_size
    for i in range(section_count):
        offset = sections_offset + i * 40

        virt_address = _decode_pe_int(binary[offset + 12:offset + 16])
        virt_address += image_base
        virt_size = _decode_pe_int(binary[offset + 8:offset + 12])
        if virtual_address < virt_address:
            continue
        if virtual_address >= virt_address + virt_size:
            continue
        virtual_offset = virtual_address - virt_address

        file_offset = _decode_pe_int(binary[offset + 20:offset + 24])
        data_size = _decode_pe_int(binary[offset + 16:offset + 20])
        section_data = binary[file_offset:file_offset + data_size]
        if virt_size > data_size:
            section_data += b'\0' * (virt_size - data_size)

        return section_data[virtual_offset:virtual_offset + length]
    return None
