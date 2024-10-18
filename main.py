import idautils
import idaapi
import idc
import tkinter as tk
from tkinter import filedialog

def dump_offsets(filename):
    if filename.endswith(('.c', '.h')):
        syntax = 'c'
    elif filename.endswith(('.cpp', '.hpp')):
        syntax = 'cpp'
    else:
        print("Unsupported file extension. Defaulting to C++")
        syntax = 'cpp'

    with open(filename, 'w') as f:
        if syntax == 'c':
            f.write("#include <stdint.h>\n\n")
            f.write("const uint32_t function_offsets[] = {\n")
        else:  # C++
            f.write("#include <cstdint>\n\n")
            f.write("constexpr uint32_t function_offsets[] = {\n")

        for function_ea in idautils.Functions():
            function_name = idc.get_func_name(function_ea)
            offset = function_ea - idaapi.get_imagebase()
            f.write(f"    {hex(offset)}, // {function_name}\n")

        f.write("};\n\n")

        if syntax == 'c':
            f.write("const uint32_t data_offsets[] = {\n")
        else:  # C++/Other
            f.write("constexpr uint32_t data_offsets[] = {\n")

        for seg_ea in idautils.Segments():
            seg = idaapi.getseg(seg_ea)
            if seg is not None and seg.type == idaapi.SEG_DATA:
                for data_ea in idautils.DataRefsFrom(seg_ea):
                    data_name = idc.get_name(data_ea)
                    offset = data_ea - idaapi.get_imagebase()
                    f.write(f"    {hex(offset)}, // {data_name}\n")

                for item_ea, item_name in idautils.Names():
                    if seg.start_ea <= item_ea < seg.end_ea:
                        var_name = idc.get_name(item_ea)
                        var_offset = item_ea - idaapi.get_imagebase()
                        f.write(f"    {hex(var_offset)}, // Variable: {var_name}\n")

        f.write("};\n")

def s():
    root = tk.Tk()
    root.withdraw()

    file_path = filedialog.asksaveasfilename(
        defaultextension=".cpp",
        filetypes=[("C++ Files", "*.cpp"), ("C Files", "*.c"), ("All Files", "*.*")]
    )

    return file_path

output_file = s()

if output_file:
    dump_offsets(output_file)
    print(f"Offsets have been written to {output_file}")
else:
    print("No file selected. Offsets not written.")