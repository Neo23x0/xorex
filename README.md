# XOREX

XOR Key Evaluator for Encrypted Executables

## Usage

       _  ______  ___  _____  __
      | |/_/ __ \/ _ \/ __/ |/_/
     _>  </ /_/ / , _/ _/_>  <
    /_/|_|\____/_/|_/___/_/|_|

    XOR Key Evaluator for Encrypted Executables
    Florian Roth, July 2020, 0.2.0

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

Xorex is a tool designed for performing statistical analysis on files to extract potential XOR keys based on their frequency of occurrence. Given that Portable Executable (PE) files often contain sections with sequences of binary zeros, the XOR key can often be identified by its frequent appearance in the file.

To identify potential XOR keys, Xorex first performs an analysis of the file's byte distribution. The tool then validates these candidates by applying them to a portion of the data, searching for typical MS-DOS header stubs.

Additionally, Xorex attempts to locate an MZ header, which can help detect junk code or shellcode preceding the actual PE file. This process allows the tool to adjust the offset and refine the preliminary XOR key to a more accurate version.

## Get Started

1. Git clone the repo and cd into it `git clone https://github.com/Neo23x0/xorex.git && cd xorex`
2. Install requirements `pip install -r requirements.txt`
3. Try it with the demo files `python xorex.py -f ./examples/mustang-1.xored`
4. Check the output files in the `./output` folder

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
