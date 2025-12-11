from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


FUNCTION_FILTER = {'register_tm_clones', 'deregister_tm_clones', 'frame_dummy'}

class GhidraExport:
    def __init__(self, program):
        self.program = program
        self.ifc = DecompInterface()
        self.ifc.openProgram(program)
        self.monitor = ConsoleTaskMonitor()


    def get_functions(self, include_system=False):
        user_funcs = []
        for func in self.program.getFunctionManager().getFunctions(True):
            fname = func.getName()
            if include_system or (func.getSignatureSource() != SourceType.IMPORTED and fname[0] != '_' and fname not in FUNCTION_FILTER):
                user_funcs.append(func)
        return user_funcs

    def get_func_decompilation(self, f):
        source = "/* ===== Function: {} @ {} ===== */\n".format(f.getName(), f.getEntryPoint())

        try:
            res = self.ifc.decompileFunction(f, 0, self.monitor)
            if res is None or res.getDecompiledFunction() is None:
                body = "/* Failed to decompile {} */\n".format(f.getName())
            else:
                body = res.getDecompiledFunction().getC()

            source += body
        except Exception as e:
            source += "/* Error decompiling {}: {} */\n\n".format(f.getName(), e)

        return source

    def get_decompilation(self, include_system=False):
        funcs = self.get_functions(include_system)
        decompiled_source = []

        for f in sorted(funcs, key=lambda x: x.getEntryPoint()):
            decompiled_source.append(self.get_func_decompilation(f))

        return ''.join(decompiled_source)

