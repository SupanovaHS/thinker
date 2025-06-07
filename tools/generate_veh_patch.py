import pandas as pd
from pathlib import Path

VEH_BASE = 0x00952828
NEW_VEH_COUNT = 8192
NEW_VEH_SIZE = 0x34
NEW_VEH_TOTAL_SIZE = NEW_VEH_COUNT * NEW_VEH_SIZE

veh_offsets_df = pd.read_csv("veh_disp_offsets.tsv", sep="\t")

cpp_lines = [
    '#include "patch.h"',
    '#include <vector>',
    '#include <cstdint>',
    '',
    f'uintptr_t new_VEH_addr = reinterpret_cast<uintptr_t>(malloc({NEW_VEH_TOTAL_SIZE}));',
    'if (!new_VEH_addr) exit_fail(0);',
    '',
    'void apply_veh_patches() {'
]

for _, row in veh_offsets_df.iterrows():
    addr = int(row['address'], 16)
    disp_offset = int(row['disp_offset'])
    old_bytes = [f"0x{b}" for b in row['old_bytes'].split()]
    veh_offset = int(row['veh_offset'], 16)
    old_bytes_str = ", ".join(old_bytes)

    cpp_lines += [
        f'    // {row["function"]} - {row["instruction"]}',
        f'    build_patch(0x{addr:08X}, std::vector<uint8_t>{{{old_bytes_str}}}, {disp_offset}, new_VEH_addr + 0x{veh_offset:X});'
    ]

cpp_lines += ['}', '']

cpp_lines += [
    'void build_patch(int32_t targetAddr, const std::vector<uint8_t>& old_bytes, int disp_offset, uintptr_t new_ptr) {',
    '    std::vector<uint8_t> patch_bytes = old_bytes;',
    '',
    '    uint32_t new_disp = static_cast<uint32_t>(new_ptr);',
    '    patch_bytes[disp_offset]     =  new_disp & 0xFF;',
    '    patch_bytes[disp_offset + 1] = (new_disp >> 8) & 0xFF;',
    '    patch_bytes[disp_offset + 2] = (new_disp >> 16) & 0xFF;',
    '    patch_bytes[disp_offset + 3] = (new_disp >> 24) & 0xFF;',
    '',
    '    while (patch_bytes.size() < old_bytes.size()) patch_bytes.push_back(0x90);',
    '    write_bytes(targetAddr, old_bytes.data(), patch_bytes.data(), static_cast<int32_t>(old_bytes.size()));',
    '}'
]

Path("vehPatch.cpp").write_text("\n".join(cpp_lines))
Path("vehPatch.h").write_text("""#pragma once

#include <vector>
#include <cstdint>

void apply_veh_patches();
void build_patch(int32_t targetAddr, const std::vector<uint8_t>& old_bytes, int disp_offset, uintptr_t new_ptr);
""")
