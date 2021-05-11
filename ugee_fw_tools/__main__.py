import ugee_fw_tools.key as key
import ugee_fw_tools.sm4 as sm4

__all__ = ('main',)


def main():
    with open('UgeeBootLoader.exe', 'rb') as exefile:
        exe = exefile.read()
    sm4_key = key.extract_key(exe)
    if not sm4_key:
        return 1

    with open('Bootloader-tool.enc', 'rb') as infofile:
        info = infofile.read()
    info = sm4.sm4_transcrypt(info, sm4_key, True)
    if not info:
        return 1
    with open('Bootloader-tool.bin', 'wb') as outfile:
        outfile.write(info)

    filename = info[10:]
    filename = filename[:filename.find(b'\0')]
    filename = filename.decode()

    with open('bin/' + filename, 'rb') as fwfile,\
            open('bin/' + filename.replace('enc', ''), 'wb') as outfile:
        sm4.sm4_transcrypt(fwfile, sm4_key, True, output_file=outfile)
    return 0


if __name__ == '__main__':
    raise SystemExit(main() or 0)
