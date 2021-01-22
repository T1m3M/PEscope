# PEscope

PEscope is a simple tool for doing a basic static analysis to a PE file with a colorful CLI


# Introduction

Instead of wasting the analysis time in basic static analysis by checking the sample using the various tools out there, I decided to write a tool to perform the analysis given the sample in an organized way and most importantly with colors!


## Usage

The tool is written in Python and with the source code you can run it as a normal python file!

> NOTE: If you are going with the source make sure you have python3.x installed and [pefile library](https://pypi.org/project/pefile/) using ```pip install pefile```


### Windows

For 64-bit Windows you can use the pre-compiled executable [pescope.exe](dist/) in the dist directory, you can add the path to the ```PATH``` environment variable to use it from anywhere too.

```console
> pescope foo.exe
```

If you're having a problem with the executable or a 32-bit Windows user this will do:

```console
> python3 pescope.py foo.exe

```


### Linux

First you need to give it the execute permission as follows:

```terminal
$ chmod +x pescope.py
```

Then you can use it as a python script:

```terminal
$ python3 pescope.py foo.exe
```

If you want to run it from anywhere you can do:

```terminal
$ sudo cp pescope.py /usr/bin/pescope
```

