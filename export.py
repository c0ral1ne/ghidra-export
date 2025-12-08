#@runtime PyGhidra

from javax.swing import JFileChooser
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

FUNCTION_FILTER = {'register_tm_clones', 'deregister_tm_clones', 'frame_dummy'}

ifc = DecompInterface()
ifc.openProgram(currentProgram)


def get_user_functions():
    user_funcs = {}
    for func in currentProgram.getFunctionManager().getFunctions(True):
        fname = func.getName()
        if func.getSignatureSource() != SourceType.IMPORTED and fname[0] != '_' and fname not in FUNCTION_FILTER:
            user_funcs[fname] = func
    return user_funcs

def get_decomp(func):
    results = ifc.decompileFunction(func, 0, ConsoleTaskMonitor())
    source = results.getDecompiledFunction().getC()
    return source

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

    ufs = get_user_functions()
    decompiled_source = []
    if 'main' in ufs:
        decompiled_source.append(get_decomp(ufs['main']))
        del ufs['main']

    for f in ufs.values():
        decompiled_source.append(get_decomp(f))

    decompiled = ''.join(decompiled_source)
    fpath = f'{output_dir}/decompiled.c'
    with open(fpath, 'w') as file:
        file.write(decompiled)

    print("Exported decompiled source code to ", fpath)

run()

