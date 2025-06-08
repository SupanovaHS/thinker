from ghidra.program.model.listing import Function
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.script import GhidraScript
from java.io import FileWriter, BufferedWriter

import os

def from_bytes_le(b):
    return (b[0] & 0xFF) | ((b[1] & 0xFF) << 8) | ((b[2] & 0xFF) << 16) | ((b[3] & 0xFF) << 24)

VEH_BASE = 0x00952828
VEH_LIMIT = VEH_BASE + 0x34 * 2048
OUTPUT_FILE = "veh_disp_offsets.tsv"
SKIPPED_LOG = "veh_skipped_instructions.log"

listing = currentProgram.getListing()
monitor = ConsoleTaskMonitor()

out_dir = getSourceFile().getParentFile().getAbsolutePath()
out_file = os.path.join(out_dir, OUTPUT_FILE)
skip_file = os.path.join(out_dir, SKIPPED_LOG)

bw = BufferedWriter(FileWriter(out_file))
bw.write("address\tfunction\tmnemonic\tinstruction\told_bytes\tdisp_offset\tveh_offset\tdisp_value\n")

sw = BufferedWriter(FileWriter(skip_file))

instr_iter = listing.getInstructions(True)

while instr_iter.hasNext() and not monitor.isCancelled():
    instr = instr_iter.next()
    addr = instr.getAddress()
    mnem = instr.getMnemonicString()
    func = listing.getFunctionContaining(addr)
    func_name = func.getName() if func else "<unknown>"

    bytes_array = instr.getBytes()
    old_bytes = " ".join("%02X" % (b & 0xFF) for b in bytes_array)
    disp_offset = -1
    disp_val = None
    veh_offset = None
    found_valid_ref = False

    refs = instr.getReferencesFrom()
    for ref in refs:
        to_addr = ref.getToAddress().getOffset()
        if VEH_BASE <= to_addr < VEH_LIMIT:
            disp_val = to_addr
            veh_offset = disp_val - VEH_BASE
            found_valid_ref = True

            for i in range(len(bytes_array) - 3):
                try:
                    val = from_bytes_le(bytes_array[i:i+4])
                    if val == disp_val:
                        disp_offset = i
                        break
                except:
                    continue

            if disp_offset == -1:
                # fallback for SIB encoded offsets like MOV CX, word ptr [ECX*4 + disp32]
                try:
                    for i in range(len(bytes_array) - 3):
                        val = from_bytes_le(bytes_array[i:i+4])
                        if val == disp_val:
                            disp_offset = i
                            break
                except:
                    pass

            bw.write("%s\t%s\t%s\t%s\t%s\t%d\t0x%X\t0x%X\n" % (
                addr, func_name, mnem, instr.toString(), old_bytes, disp_offset, veh_offset, disp_val
            ))
            break

    if not found_valid_ref:
        # Check pcode references (covers computed/SIB references)
        pcode = instr.getPcode()
        for op in pcode:
            for input in op.getInputs():
                try:
                    val = input.getOffset()
                    if VEH_BASE <= val < VEH_LIMIT:
                        disp_val = val
                        veh_offset = disp_val - VEH_BASE
                        found_valid_ref = True

                        for i in range(len(bytes_array) - 3):
                            try:
                                val2 = from_bytes_le(bytes_array[i:i+4])
                                if val2 == disp_val:
                                    disp_offset = i
                                    break
                            except:
                                continue

                        bw.write("%s\t%s\t%s\t%s\t%s\t%d\t0x%X\t0x%X\n" % (
                            addr, func_name, mnem, instr.toString(), old_bytes, disp_offset, veh_offset, disp_val
                        ))
                        break
                except:
                    continue
            if found_valid_ref:
                break

    if not found_valid_ref:
        sw.write("SKIPPED: %s\t%s\t%s\t%s\n" % (
            addr, func_name, mnem, old_bytes
        ))

bw.close()
sw.close()
print("Done. Output saved to %s\nSkipped instructions logged to %s" % (out_file, skip_file))
