# ghidra-export

Export decompiled functions into a single C file.

## Install
1. Clone repo
2. Put `export.py` into one of Ghidra's script directories. The default directory should be in your home directory.

All done! You can verify the script is being properly picked up by opening Ghidra -> Script Manager and searching for `export.py`

## Usage
Since this is a Pyghidra script, you'll need to start Ghidra using the `pyghidraRun` script instead of the typical `ghidraRun`.

In Ghidra with a project binary open, you can launch the script through the Script Manager. For convenience, you can assign it a key-binding, You should also see it in the Script menu dropdown after the first time you run it.

<todo pictures/gif>

## Todo
* Support CLI headless mode
* Better script title and description
* Better readme
