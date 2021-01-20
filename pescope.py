import os
import sys
import hashlib
import pefile

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
    pink = '\033[95m'
    lightRed = '\033[91m'
    lightGreen = '\033[92m'
    lightBlue = '\033[94m'
    lightCyan = '\033[96m'


# colorizing texts
def colorize(text, color):
    print("{}{}".format(color, text) + Colors.reset)


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

    colorize("MD5    : {}".format(md5.hexdigest()), Colors.lightCyan)
    colorize("SHA1   : {}".format(sha1.hexdigest()), Colors.cyan)
    colorize("SHA256 : {}".format(sha256.hexdigest()), Colors.lightBlue)


def pe_libs(pe_):

    for lib in pe_.DIRECTORY_ENTRY_IMPORT:
        colorize('\t' + lib.dll.decode('utf-8'), Colors.lightGreen)


# PEscope interface

pe = pefile.PE(sys.argv[1])

colorize("\n--------------------------------[ Hashes ]--------------------------------\n", Colors.yellow)
pe_hashes(sys.argv[1])

colorize("\n-------------------------------[ Imports ]--------------------------------\n", Colors.pink)
pe_libs(pe)

