#pragma once
/**
 * List of PMU configurations for AMD.
 */

#include "pfc.h"

/**
 * [Retired Instructions] (Core::X86::Pmc::Core::ExRetInstr)
 * The number of instructions retired.
 */
#define UARF_AMD_EX_RET_INSTR UARF_PMU_CONFIG(.event = 0xC0, .umask = 0x00)

/**
 * [Retired Near Returns Mispredicted]
 * (Core::X86::Pmc::Core::ExRetNearRetMispred)
 * The number of near returns retired that were not correctly predicted by the return
 * address predictor. Each such mispredict incurs the same penalty as a mispredicted
 * conditional branch instruction.
 */
#define UARF_AMD_EX_RET_NEAR_RET_MISPRED UARF_PMU_CONFIG(.event = 0xC9, .umask = 0x00)

/**
 * [Retired Indirect Branch Instructions Mispredicted]
 * (Core::X86::Pmc::Core::ExRetBrnIndMisp)
 * The number of indirect branches retired that were not correctly predicted. Each such
 * mispredict incurs the same penalty as a mispredicted conditional branch instruction.
 * Note that only EX mispredicts are counted.
 */
#define UARF_AMD_EX_RET_BRN_IND_MISP UARF_PMU_CONFIG(.event = 0xCA, .umask = 0x00)

/*
 * [Retired Indirect Branch Instructions] (Core::X86::Pmc::Core::ExRetIndBrchInstr)
 * The number of indirect branches retired.
 */
#define UARF_AMD_EX_RET_IND_BRCH_INSTR UARF_PMU_CONFIG(.event = 0xCC, .umask = 0x00)
