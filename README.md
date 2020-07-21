# XOREX

XOR Key Evaluator for Encrypted Executables

## Usage

    usage: xorex.py [-h] [-f input files [input files ...]] [-w max-window-size] [-m max-offset] [--debug]
    
    XOR Key Extractor
    
    optional arguments:
      -h, --help            show this help message and exit
      -f input files [input files ...]
                            Path to input files
      -w max-window-size    Window Size (max. XOR key size)
      -m max-offset         Maximum look into the file
      --debug               Debug output
      
## The Idea

The idea is to run some statistical analysis on the file to extract possible keys based on their frequency of occurrence. Since Portable Executables (PE files) often contain ranges of binary zeros, we can assume that we find the XOR key more often than other byte chains.

I validate the possible candidates by applying them to a portion of the data blob looking for typical MS-DOS header stubs. 

Furthermore, I then try to find a MZ header in order to detect junk code or shellcode before the actual PE file, adjusting the offset and rotating the preliminary XOR key to its more likely version. 

## Screenshots

![Screen 1](/screens/screen1.png)

![Screen 2](/screens/screen2.png)

![Screen 3](/screens/screen3.png)

## Known Issues

- This only works with static XOR keys
- The script currently only works with encrypted Windows executables

## Warning 

Consider this code as Proof-of-Concept. I had 3 hours to write it and used it for the single purpose of decrypting a sample related to the Mustang Panda threat group, but thought that it could be helpful to have such a script for other XORed executables. 

If you have more time to spend and decide to build something similar or better, please let me know.

## Contact 

Follow [me](https://twitter.com/cyb3rops) on Twitter