#@runtime PyGhidra

from javax.swing import JFileChooser
from utils import GhidraExport


def choose_output_directory():
    chooser = JFileChooser()
    chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY)
    chooser.setDialogTitle("Export to directory")

    result = chooser.showOpenDialog(None)
    if result == JFileChooser.APPROVE_OPTION:
        return chooser.getSelectedFile().getAbsolutePath()
    return None


def run():
    output_dir = choose_output_directory()

    export = GhidraExport(currentProgram)
    decompiled = export.get_decompilation()

    fpath = f'{output_dir}/decompiled.c'
    with open(fpath, 'w') as file:
        file.write(decompiled)

    print("Exported decompiled source code to ", fpath)

if __name__ == '__main__':
    run()

