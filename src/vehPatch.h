#pragma once

#include <vector>
#include <cstdint>

void apply_veh_patches();
void build_patch(int32_t targetAddr, const std::vector<uint8_t>& old_bytes, int disp_offset, const uintptr_t new_ptr);
