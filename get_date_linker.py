from pelinker import Executable
import sys

exe = Executable()

text = exe.add_section(".text", "rx")
with open(sys.argv[1], "rb") as opcodes:
    text.content = opcodes.read()

data = exe.add_section(".data", "rw")
data.content = b"system_time SYSTEMTIME 0" # Initialization at 0 of every field about SYSTEMTIME structure.

format = exe.add_section(".format", "r")
format.content = b"Today Date: %d/%d/%d" # Format about integer numbers (32 bit).

exe.entry_point = text.rva

exe.import_symbols("kernel32.dll", ["GetLocalTime", "Sleep", "ExitProcess"])
exe.import_symbols("msvcrt.dll", ["printf"])
exe.export_symbol("main", text.rva)

with open(sys.argv[2], "wb") as output:
    output.write(exe.link())