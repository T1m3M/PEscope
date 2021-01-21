import os
import sys
import hashlib
import pefile
from random import randint

os.system("COLOR")

# CONSTANTS
BUF_SIZE = 65536


class Colors:
    reset = '\033[0m'
    green = '\033[32m'
    orange = '\033[33m'
    blue = '\033[34m'
    purple = '\033[35m'
    cyan = '\033[36m'
    yellow = '\033[93m'
    pink = '\033[38;5;171m'
    lightRed = '\033[91m'
    lightGreen = '\033[92m'
    lightBlue = '\033[94m'
    lightCyan = '\033[96m'
    bgCyanB = '\033[6;30;46m'
    bgRedB = '\033[6;30;101m'
    bgGreenB = '\033[6;30;102m'
    bgYellowB = '\033[6;30;103m'
    bgBlueB = '\033[6;30;104m'
    bgDarkYellowB = '\033[6;30;43m'
    bgDarkGreenB = '\033[6;30;42m'
    bgPink = '\033[48;5;165m'
    bgPurple = '\033[48;5;129m'
    bgBlue = '\033[48;5;20m'


# colorizing texts
def colorize(text, color):
    print("{}{}".format(color, text) + Colors.reset)


# random color per character
def random_colors(text):
    colors = [
        Colors.orange,
        Colors.lightGreen,
        Colors.lightBlue,
        Colors.lightCyan,
        Colors.lightRed,
        Colors.yellow,
        Colors.pink,
        Colors.cyan
    ]
    for letter in text:
        r_ = randint(0, len(colors) - 1)
        print("{}{}".format(colors[r_], letter), end='')

    print(Colors.reset)


# help
def help():

    print("\n\t\t\t  ", end='')
    random_colors('PEscope Tool')

    print("""
    Usage: pescope [options] <file>
    \t Performs a basic static analysis to the sample provided\n
    
    options:
    \t -h, --help
    \t\t Display help\n
    \t -i, --info
    \t\t Display general information about the sample\n
    \t -l, --libs
    \t\t Print the imported libraries\n
    \t -s, --sections
    \t\t View the file's sections\n
    \t -H, --hash
    \t\t Print the file's hashes (md5, sha1, sha256)\n
    \t -I, --imports
    \t\t Print all the imports\n
    """)


# Print the file's hashes
def pe_hashes(filename):

    # hashes generated
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(filename, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)

    colorize("\n--------------------------------[ Hashes ]--------------------------------\n", Colors.yellow)
    colorize("MD5    : {}".format(md5.hexdigest()), Colors.lightCyan)
    colorize("SHA1   : {}".format(sha1.hexdigest()), Colors.cyan)
    colorize("SHA256 : {}".format(sha256.hexdigest()), Colors.lightBlue)


# Print the imports
def pe_libs(pe_, print_all):

    if print_all:
        colorize("\n-------------------------------[ Imports ]--------------------------------\n", Colors.pink)
    else:
        colorize("\n--------------------------[ Imported Libraries ]--------------------------\n", Colors.lightRed)

    for lib in pe_.DIRECTORY_ENTRY_IMPORT:

        if print_all:
            colorize(" " + lib.dll.decode('utf-8') + " ", Colors.bgCyanB)
        else:
            colorize("[-] " + lib.dll.decode('utf-8'), Colors.orange)

        if print_all:
            for func in lib.imports:
                colorize("\t- " + func.name.decode('utf-8'), Colors.cyan)
            print('\n')


# specify the section permission's based on the byte value
def sec_perm(perm):

    p = int(perm, 16)
    permissions = []
    result = ''

    # extracting the permission
    if p >= 8:
        permissions.append('W')
        p -= 8

    if p >= 4:
        permissions.append('R')
        p -= 4

    if p >= 2:
        permissions.append('X')
        p -= 2

    # rewriting the permissions as linux format
    if 'R' in permissions:
        result += 'R'
    if 'W' in permissions:
        result += 'W'
    if 'X' in permissions:
        result += 'X'

    return result


# Print the file's sections
def pe_sections(pe_):

    headers = [
        ['Section Name', Colors.bgCyanB],
        ['Virtual Addr.', Colors.bgRedB],
        ['Virutal Size', Colors.bgYellowB],
        ['Raw Size', Colors.bgGreenB],
        ['Ptr to Raw', Colors.bgDarkYellowB],
        ['Perms', Colors.bgBlueB]
    ]

    colorize("\n-------------------------------[ Sections ]-------------------------------\n", Colors.lightGreen)

    print(' ', end='')
    for i in range(0, len(headers)):
        print(headers[i][1] + " " + headers[i][0] + " {}".format(Colors.reset), end='')
    print('')

    row_colors = [Colors.pink, Colors.bgPurple]
    i = 0

    for section in pe_.sections:
        print(" {0}{1}{2}".format(row_colors[i%2], section.Name.decode('utf-8').strip(u'\u0000').ljust(len(headers[0][0]) + 2), Colors.reset), end='')
        print("{0}{1}{2}".format(row_colors[i%2], hex(section.VirtualAddress).ljust(len(headers[1][0]) + 2), Colors.reset), end='')
        print("{0}{1}{2}".format(row_colors[i%2], hex(section.Misc_VirtualSize).ljust(len(headers[2][0]) + 2), Colors.reset), end='')
        print("{0}{1}{2}".format(row_colors[i%2], hex(section.SizeOfRawData).ljust(len(headers[3][0]) + 2), Colors.reset), end='')
        print("{0}{1}{2}".format(row_colors[i%2], hex(section.PointerToRawData).ljust(len(headers[4][0]) + 2), Colors.reset), end='')
        print("{0}  {1}{2}".format(row_colors[i%2], sec_perm(hex(section.Characteristics)[2]).ljust(len(headers[5][0])), Colors.reset), end='')
        print("")
        i += 1


def pe_info(pe_):
    print('info')


# PEscope interface

if len(sys.argv) == 1 or (len(sys.argv) == 2 and (sys.argv[1] == '-h' or sys.argv[1] == '--help')):
    help()

elif len(sys.argv) >= 2:
    if os.path.isfile(sys.argv[-1]) and os.access(sys.argv[-1], os.X_OK):

        try:
            pe = pefile.PE(sys.argv[-1], fast_load=True)

            if len(sys.argv) == 2:

                pe.full_load()

                pe_hashes(sys.argv[-1])
                pe_info(pe)
                pe_libs(pe, False)
                pe_libs(pe, True)
                pe_sections(pe)

            elif len(sys.argv) > 2:
                if '-H' in sys.argv or '--hash' in sys.argv:
                    pe_hashes(sys.argv[-1])

                if '-i' in sys.argv or '--info' in sys.argv:
                    pe_info(pe)

                if '-l' in sys.argv or '--libs' in sys.argv:
                    pe.parse_data_directories()
                    pe_libs(pe, False)

                if '-I' in sys.argv or '--imports' in sys.argv:
                    pe.parse_data_directories()
                    pe_libs(pe, True)

                if '-s' in sys.argv or '--sections' in sys.argv:
                    pe_sections(pe)

        except pefile.PEFormatError:
            colorize(f"Error: Only PE files are supported", Colors.lightRed)
            exit(0)

    else:
        colorize('Error: Invalid executable file!', Colors.lightRed)
