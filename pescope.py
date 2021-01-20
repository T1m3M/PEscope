import os

os.system("COLOR")


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


def colorize(text, color):
    print("{}{}".format(color, text) + Colors.reset)


