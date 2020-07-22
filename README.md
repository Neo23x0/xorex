# XOREX

XOR Key Evaluator for Encrypted Executables

## Usage

    usage: xorex.py [-h] [-f input_file] [-w max-window-size] [-m max-offset] [-o output-path] [--debug]
    
    XOR Key Extractor
    
    optional arguments:
      -h, --help          show this help message and exit
      -f input_file       Path to input file
      -w max-window-size  Window Size (max. XOR key size)
      -m max-offset       Maximum look into the file
      -o output-path      Output Path for decrypted PE files
      --debug             Debug output
      
## The Idea

The idea is to run some statistical analysis on the file to extract possible keys based on their frequency of occurrence. Since Portable Executables (PE files) often contain ranges of binary zeros, we can assume that we find the XOR key more often than other byte chains.

I validate the possible candidates by applying them to a portion of the data blob looking for typical MS-DOS header stubs. 

Furthermore, I then try to find a MZ header in order to detect junk code or shellcode before the actual PE file, adjusting the offset and rotating the preliminary XOR key to its more likely version. 

## Screenshots

![Screen 1](/screens/screen1.png)

![Screen 2](/screens/screen2.png)

File Recovery - new in v0.2

![Screen 4](/screens/screen4.png)

## Known Issues

- This only works with static XOR keys
- The script currently only works with encrypted Windows executables

## Warning 

Consider this code as Proof-of-Concept. I had 3 hours to write it and used it for the single purpose of decrypting a sample related to the Mustang Panda threat group [[1]](https://app.threatconnect.com/auth/indicators/details/file.xhtml?file=1055EAF96CEAAB38F082068B7382D27E2F944595666FC7AA2BB4B32073A1D668&owner=Common%20Community#/) [[2]](https://blog.malwarebytes.com/threat-analysis/2020/06/multi-stage-apt-attack-drops-cobalt-strike-using-malleable-c2-feature/), but thought that it could be helpful to have such a script for other XORed executables. 

If you have more time to spend and decide to build something similar or better, please let me know.

## Contact 

Follow [me](https://twitter.com/cyb3rops) on Twitter