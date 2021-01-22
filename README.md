![PEscope Cover](/assets/PEscope-cover.png)

# PEscope

PEscope is a simple tool for doing a basic static analysis to a PE file with a colorful CLI


## Introduction

Instead of wasting the analysis time in basic static analysis by checking the sample using the various tools out there, I decided to write my own tool to perform the analysis in an organized way and most importantly with colors!

Here you can find a full walkthrough with the tool on my blog: https://T1m3M.github.io/posts/PEscope-tool


## Features

Here is the list of the options you can use:

```
    Usage: pescope [options] <file>
         Performs a basic static analysis to the sample provided


    options:
         -c
                 No colors

         -h, --help
                 Display help

         -i, --info
                 Display general information about the sample

         -l, --libs
                 Print the imported libraries

         -m, --match <regex>
                 Match strings with a regular expression

         -s, --sections
                 View the file's sections

         -H, --hash
                 Print the file's hashes (md5, sha1, sha256)

         -I, --imports
                 Print all the imports

         -S, --strings
                 View the file's interesting strings (IPs, URLs, emails, errors, ...)


    Examples:
         pescope foo.exe (perform full analysis)
         pescope -i -l -s bar.dll
         pescope -H -m [a-zA-Z]{5,}[\d]$ foo.exe
```

## Usage

The tool is written in Python and with the source code you can run it as a normal python file!

> NOTE: If you are going with the source make sure you have python3.x installed and [pefile library](https://pypi.org/project/pefile/) using ```pip install pefile```


![PEscope on Windows and Linux](/assets/pescope-win-linux.jpg)


## Windows

For 64-bit Windows you can use the pre-compiled executable [pescope.exe](dist/) in the dist directory, you can add the path to the ```PATH``` environment variable to use it from anywhere too.

```console
> pescope foo.exe
```

If you're having a problem with the executable or a 32-bit Windows user this will do:

```console
> python3 pescope.py foo.exe

```


## Linux

First you need to give it the execute permission as follows:

```terminal
$ chmod +x pescope.py
```

Then you can use it as a python script:

```terminal
$ python3 pescope.py foo.exe
```

Or if you want to run it from anywhere you can do:

```terminal
$ sudo cp pescope.py /usr/bin/pescope
```

