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
    bgCyan = '\033[6;30;46m'


# colorizing texts
def colorize(text, color):
    print("{}{}".format(color, text) + Colors.reset)


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
    \t -l, --libs
    \t\t Print the imported libraries\n
    \t -H, --hash
    \t\t Print the file's hashes (md5, sha1, sha256)\n
    \t -I, --imports
    \t\t Print all the imports\n
    """)


# calculating the file's hashes
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


def pe_libs(pe_, print_all):

    if print_all:
        colorize("\n-------------------------------[ Imports ]--------------------------------\n", Colors.pink)
    else:
        colorize("\n--------------------------[ Imported Libraries ]--------------------------\n", Colors.lightRed)

    for lib in pe_.DIRECTORY_ENTRY_IMPORT:

        if print_all:
            colorize(" " + lib.dll.decode('utf-8') + " ", Colors.bgCyan)
        else:
            colorize("[-] " + lib.dll.decode('utf-8'), Colors.orange)

        if print_all:
            for func in lib.imports:
                colorize("\t- " + func.name.decode('utf-8'), Colors.cyan)
            print('\n')


# PEscope interface

if len(sys.argv) == 1 or (len(sys.argv) == 2 and (sys.argv[1] == '-h' or sys.argv[1] == '--help')):
    help()

elif len(sys.argv) >= 2:
    if os.path.isfile(sys.argv[-1]) and os.access(sys.argv[-1], os.X_OK):

        pe = pefile.PE(sys.argv[-1], fast_load=True)

        if len(sys.argv) == 2:

            pe_hashes(sys.argv[-1])
            pe_libs(pe, False)
            pe_libs(pe, True)

        elif len(sys.argv) > 2:
            if '-H' in sys.argv or '--hash' in sys.argv:
                pe_hashes(sys.argv[-1])

            if '-l' in sys.argv or '--libs' in sys.argv:
                pe_libs(pe, False)

            if '-I' in sys.argv or '--imports' in sys.argv:
                pe_libs(pe, True)

    else:
        colorize('Error: Invalid executable file!', Colors.lightRed)
