# PEscope

PEscope is a simple tool for doing a basic static analysis to a PE file with a colorful CLI


# Introduction

Instead of wasting the analysis time in basic static analysis by checking the sample using the various tools out there, I decided to write a tool to perform the analysis given the sample in an organized way and most importantly with colors!


## Usage

The tool is written in Python and with the source code you can run it as a normal python file!

### Windows

For 64-bit Windows you can use the pre-compiled executable [pescope.exe](dist/pescope.exe) and you can add the path to the ```PATH``` environment variable to use it from anywhere

```console
> pescope foo.exe
```

If you're having a problem with the executable or a 32-bit Windows user this will do:

```console
> python3 pescope.py foo.exe

```
> NOTE: Make sure you have python3.x installed and [pefile library](https://pypi.org/project/pefile/) using ```pip install pefile``` 
