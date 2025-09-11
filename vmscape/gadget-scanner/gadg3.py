#!/usr/bin/env python3

import copy
import os
import re
import sys
import pprint
from concurrent.futures import ThreadPoolExecutor
from subprocess import check_output
from typing import Generator, Optional

from alive_progress import alive_bar
from capstone import CS_ARCH_X86, CS_MODE_64, CS_MODE_LITTLE_ENDIAN, Cs, CsInsn, x86
from elftools.elf import sections
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

TEST_MODE = os.environ.get("TEST", False)
DEBUG = TEST_MODE or os.environ.get("DEBUG", False)

THREADS = 8
JOB_CHUNK = 0x1000
CODE_VIEW_SIZE = 0x100
MAX_GADGET_SIZE = 4
SECRET_LOAD_SIZES = [1, 2]
# SECRET_LOAD_SIZES = [1, 2, 4, 8]

ENABLE_FR = True
ENABLE_PP = False
ENABLE_BTB = False
ENABLE_JOP = False  # find useful gadgets for gadget chaining
ENABLE_DUMB = False
ENABLE_LIBRARIES = False  # not TEST_MODE


class Range:
    def __init__(self, min: int, max: int = None) -> None:
        self.min: int = min
        self.max: int = max if max is not None else min

    def add(self, val: int) -> None:
        self.min += val
        self.max += val

    def disp_in_range(self, disp: int) -> bool:
        return self.min <= disp and disp <= self.max

    def __repr__(self):
        return f"Range({hex(self.min)},{hex(self.max)})"


class RegisterState:
    def __init__(
        self,
        value_range=None,
        mem_control=None,
        attacker_ptr=False,
        secret_ptr=False,
        secret=False,
        tainted=False,
    ):
        # store knowledge about the value in the register
        self.value_range: Optional[Range] = value_range
        # store knowledge about control over memory at the register (range around the pointer)
        self.mem_control: Optional[Range] = mem_control

        # whether this register contains an attacker controlled value
        self.attacker_ptr: bool = attacker_ptr
        # whether this register contains a pointer to a secret
        self.secret_ptr: bool = secret_ptr
        # whether this register contains a secret
        self.secret: bool = secret
        # whether this register is a tainted, attacker controlled value (dereferencing this is a win)
        self.tainted: bool = tainted

    def is_predictable(self):
        return self.attacker_ptr or (self.value_range is not None)

    def add(self, amount):
        if self.value_range is not None:
            self.value_range.add(amount)
        if self.mem_control is not None:
            debug_print(f"Before adding {amount} to {repr(self.mem_control)}")
            self.mem_control.add(-amount)
            debug_print(f"After adding {amount} to {repr(self.mem_control)}")

    def overwrite(self, other: "RegisterState"):
        self.value_range = copy.deepcopy(other.value_range)
        self.mem_control = copy.deepcopy(other.mem_control)

        self.attacker_ptr = other.attacker_ptr
        self.secret_ptr = other.secret_ptr
        self.secret = other.secret
        self.tainted = other.tainted

    def merge(self, other: "RegisterState"):
        if other is None:
            return
        # TODO: cannot handle value and memory range combinating yet but make sure we scap unknown range
        if not (self.value_range and other.value_range):
            self.value_range = None

        self.attacker_ptr |= other.attacker_ptr
        self.secret_ptr |= other.secret_ptr
        self.secret |= other.secret
        self.tainted |= other.tainted
        self.tainted |= reg_combined_taint(self, other)

    def superset_of(self, other: "RegisterState"):
        if (
            self.value_range
            and other.value_range
            and not (
                self.value_range.disp_in_range(other.value_range.min)
                or self.value_range.disp_in_range(other.value_range.min)
            )
        ):
            return False
        if (
            self.mem_control
            and other.mem_control
            and not (
                self.mem_control.disp_in_range(other.mem_control.min)
                and self.mem_control.disp_in_range(other.mem_control.min)
            )
        ):
            return False

        return (
            self.attacker_ptr >= other.attacker_ptr
            and self.secret_ptr >= other.secret_ptr
            and self.secret >= other.secret
            and self.tainted >= other.tainted
            and ((self.value_range is not None) >= (other.value_range is not None))
            and ((self.mem_control is not None) >= (other.mem_control is not None))
        )

    def is_reset(self):
        return not (
            self.value_range is not None
            or self.mem_control is not None
            or self.attacker_ptr
            or self.secret_ptr
            or self.secret
            or self.tainted
        )

    def __repr__(self):
        return (
            "RegisterState("
            f"value_range={repr(self.value_range)},"
            f"mem_control={self.mem_control},"
            f"attacker_ptr={self.attacker_ptr},"
            f"secret_ptr={self.secret_ptr},"
            f"secret={self.secret},"
            f"tainted={self.tainted},"
            ")"
        )


INITIAL_REGISTER_STATE = {
    x86.X86_REG_RAX: RegisterState(value_range=Range(0x555556CE9F60)),
    x86.X86_REG_RBX: RegisterState(value_range=Range(0x5555581040B0)),
    x86.X86_REG_RCX: RegisterState(value_range=Range(0x8)),
    x86.X86_REG_RDX: RegisterState(
        mem_control=Range(-0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
        value_range=Range(-0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
        attacker_ptr=True,
        # secret_ptr=True,
    ),
    x86.X86_REG_RDI: RegisterState(
        value_range=Range(0x555558103680),
        secret_ptr=True,
    ),
    x86.X86_REG_RSI: RegisterState(value_range=Range(0x0)),
    x86.X86_REG_R8: RegisterState(value_range=Range(0x8)),
    x86.X86_REG_R9: RegisterState(value_range=Range(0xFFFFFFFFFFFFFFFF)),
    x86.X86_REG_R10: RegisterState(value_range=Range(0x8)),
    x86.X86_REG_R11: RegisterState(value_range=Range(0x0, 0x246)),
    x86.X86_REG_R12: RegisterState(
        mem_control=Range(-0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
        value_range=Range(-0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF),
        attacker_ptr=True,
        # secret_ptr=True,
    ),
    x86.X86_REG_R13: RegisterState(value_range=Range(0x0)),
    x86.X86_REG_R14: RegisterState(value_range=Range(0x8)),
    x86.X86_REG_R15: RegisterState(value_range=Range(0x8)),
}

LIB_REGEX = r".+=> (?P<path>.+) \(.+\)"

REG_64_NAMES = {
    x86.X86_REG_R8: "R8",
    x86.X86_REG_R9: "R9",
    x86.X86_REG_R10: "R10",
    x86.X86_REG_R11: "R11",
    x86.X86_REG_R12: "R12",
    x86.X86_REG_R13: "R13",
    x86.X86_REG_R14: "R14",
    x86.X86_REG_R15: "R15",
    x86.X86_REG_RAX: "RAX",
    x86.X86_REG_RBX: "RBX",
    x86.X86_REG_RCX: "RCX",
    x86.X86_REG_RDX: "RDX",
    x86.X86_REG_RDI: "RDI",
    x86.X86_REG_RSI: "RSI",
    x86.X86_REG_RBP: "RBP",
    x86.X86_REG_RSP: "RSP",
    x86.X86_REG_CR2: "CR2",
}

REG_64 = [
    x86.X86_REG_R8,
    x86.X86_REG_R9,
    x86.X86_REG_R10,
    x86.X86_REG_R11,
    x86.X86_REG_R12,
    x86.X86_REG_R13,
    x86.X86_REG_R14,
    x86.X86_REG_R15,
    x86.X86_REG_RAX,
    x86.X86_REG_RBX,
    x86.X86_REG_RCX,
    x86.X86_REG_RDX,
    x86.X86_REG_RDI,
    x86.X86_REG_RSI,
    x86.X86_REG_RBP,
    x86.X86_REG_RSP,
    x86.X86_REG_CR2,
]

REG_32 = [
    x86.X86_REG_R8D,
    x86.X86_REG_R9D,
    x86.X86_REG_R10D,
    x86.X86_REG_R11D,
    x86.X86_REG_R12D,
    x86.X86_REG_R13D,
    x86.X86_REG_R14D,
    x86.X86_REG_R15D,
    x86.X86_REG_EAX,
    x86.X86_REG_EBX,
    x86.X86_REG_ECX,
    x86.X86_REG_EDX,
    x86.X86_REG_EDI,
    x86.X86_REG_ESI,
    x86.X86_REG_EBP,
    x86.X86_REG_ESP,
]

REG_16 = [
    x86.X86_REG_R8W,
    x86.X86_REG_R9W,
    x86.X86_REG_R10W,
    x86.X86_REG_R11W,
    x86.X86_REG_R12W,
    x86.X86_REG_R13W,
    x86.X86_REG_R14W,
    x86.X86_REG_R15W,
    # including high byte (upper 8 bits of 16 bit reg)
    x86.X86_REG_AH,
    x86.X86_REG_AX,
    x86.X86_REG_BX,
    x86.X86_REG_BH,
    x86.X86_REG_CH,
    x86.X86_REG_CX,
    x86.X86_REG_DX,
    x86.X86_REG_DH,
    x86.X86_REG_DI,
    x86.X86_REG_SI,
    x86.X86_REG_BP,
    x86.X86_REG_SP,
]

REG_8 = [
    x86.X86_REG_R8B,
    x86.X86_REG_R9B,
    x86.X86_REG_R10B,
    x86.X86_REG_R11B,
    x86.X86_REG_R12B,
    x86.X86_REG_R13B,
    x86.X86_REG_R14B,
    x86.X86_REG_R15B,
    x86.X86_REG_AL,
    x86.X86_REG_BL,
    x86.X86_REG_CL,
    x86.X86_REG_DL,
    x86.X86_REG_DIL,
    x86.X86_REG_SIL,
    x86.X86_REG_BPL,
    x86.X86_REG_SPL,
]

rregmap = {
    x86.X86_REG_INVALID: x86.X86_REG_INVALID,
    # special, we control this one in many occasions
    x86.X86_REG_CR2: x86.X86_REG_CR2,
    # 64-bit to 64-bit identity
    x86.X86_REG_RAX: x86.X86_REG_RAX,
    x86.X86_REG_RBX: x86.X86_REG_RBX,
    x86.X86_REG_RCX: x86.X86_REG_RCX,
    x86.X86_REG_RDX: x86.X86_REG_RDX,
    x86.X86_REG_RSI: x86.X86_REG_RSI,
    x86.X86_REG_RDI: x86.X86_REG_RDI,
    x86.X86_REG_RBP: x86.X86_REG_RBP,
    x86.X86_REG_RSP: x86.X86_REG_RSP,
    x86.X86_REG_R8: x86.X86_REG_R8,
    x86.X86_REG_R9: x86.X86_REG_R9,
    x86.X86_REG_R10: x86.X86_REG_R10,
    x86.X86_REG_R11: x86.X86_REG_R11,
    x86.X86_REG_R12: x86.X86_REG_R12,
    x86.X86_REG_R13: x86.X86_REG_R13,
    x86.X86_REG_R14: x86.X86_REG_R14,
    x86.X86_REG_R15: x86.X86_REG_R15,
    # 32-bit to 64-bit
    x86.X86_REG_EAX: x86.X86_REG_RAX,
    x86.X86_REG_EBX: x86.X86_REG_RBX,
    x86.X86_REG_ECX: x86.X86_REG_RCX,
    x86.X86_REG_EDX: x86.X86_REG_RDX,
    x86.X86_REG_ESI: x86.X86_REG_RSI,
    x86.X86_REG_EDI: x86.X86_REG_RDI,
    x86.X86_REG_EBP: x86.X86_REG_RBP,
    x86.X86_REG_ESP: x86.X86_REG_RSP,
    x86.X86_REG_R8D: x86.X86_REG_R8,
    x86.X86_REG_R9D: x86.X86_REG_R9,
    x86.X86_REG_R10D: x86.X86_REG_R10,
    x86.X86_REG_R11D: x86.X86_REG_R11,
    x86.X86_REG_R12D: x86.X86_REG_R12,
    x86.X86_REG_R13D: x86.X86_REG_R13,
    x86.X86_REG_R14D: x86.X86_REG_R14,
    x86.X86_REG_R15D: x86.X86_REG_R15,
    # 16-bit to 64-bit
    x86.X86_REG_AX: x86.X86_REG_RAX,
    x86.X86_REG_BX: x86.X86_REG_RBX,
    x86.X86_REG_CX: x86.X86_REG_RCX,
    x86.X86_REG_DX: x86.X86_REG_RDX,
    x86.X86_REG_SI: x86.X86_REG_RSI,
    x86.X86_REG_DI: x86.X86_REG_RDI,
    x86.X86_REG_BP: x86.X86_REG_RBP,
    x86.X86_REG_SP: x86.X86_REG_RSP,
    x86.X86_REG_R8W: x86.X86_REG_R8,
    x86.X86_REG_R9W: x86.X86_REG_R9,
    x86.X86_REG_R10W: x86.X86_REG_R10,
    x86.X86_REG_R11W: x86.X86_REG_R11,
    x86.X86_REG_R12W: x86.X86_REG_R12,
    x86.X86_REG_R13W: x86.X86_REG_R13,
    x86.X86_REG_R14W: x86.X86_REG_R14,
    x86.X86_REG_R15W: x86.X86_REG_R15,
    # 8-bit to 64-bit
    x86.X86_REG_AL: x86.X86_REG_RAX,
    x86.X86_REG_BL: x86.X86_REG_RBX,
    x86.X86_REG_CL: x86.X86_REG_RCX,
    x86.X86_REG_DL: x86.X86_REG_RDX,
    x86.X86_REG_AH: x86.X86_REG_RAX,
    x86.X86_REG_BH: x86.X86_REG_RBX,
    x86.X86_REG_CH: x86.X86_REG_RCX,
    x86.X86_REG_DH: x86.X86_REG_RDX,
    x86.X86_REG_SIL: x86.X86_REG_RSI,
    x86.X86_REG_DIL: x86.X86_REG_RDI,
    x86.X86_REG_BPL: x86.X86_REG_RBP,
    x86.X86_REG_SPL: x86.X86_REG_RSP,
    x86.X86_REG_R8B: x86.X86_REG_R8,
    x86.X86_REG_R9B: x86.X86_REG_R9,
    x86.X86_REG_R10B: x86.X86_REG_R10,
    x86.X86_REG_R11B: x86.X86_REG_R11,
    x86.X86_REG_R12B: x86.X86_REG_R12,
    x86.X86_REG_R13B: x86.X86_REG_R13,
    x86.X86_REG_R14B: x86.X86_REG_R14,
    x86.X86_REG_R15B: x86.X86_REG_R15,
}

ARITH_ADD = [x86.X86_INS_ADC, x86.X86_INS_ADD, x86.X86_INS_ADCX]
ARITH_SUB = [x86.X86_INS_SUB, x86.X86_INS_SBB]
LOGIC_INS = [
    x86.X86_INS_AND,
    x86.X86_INS_ANDN,
    x86.X86_INS_OR,
    x86.X86_INS_XOR,
]
ARITH_INS = (
    [
        x86.X86_INS_SHR,
        x86.X86_INS_SHL,
        x86.X86_INS_MUL,
        x86.X86_INS_IMUL,
        x86.X86_INS_IDIV,
        x86.X86_INS_DIV,
    ]
    + ARITH_ADD
    + ARITH_SUB
)
MOV_INS = [
    x86.X86_INS_MOV,
    x86.X86_INS_MOVABS,
    x86.X86_INS_MOVAPD,
    x86.X86_INS_MOVAPS,
    x86.X86_INS_MOVBE,
    x86.X86_INS_MOVDDUP,
    x86.X86_INS_MOVDIR64B,
    x86.X86_INS_MOVDIRI,
    x86.X86_INS_MOVDQA,
    x86.X86_INS_MOVDQU,
    x86.X86_INS_MOVHLPS,
    x86.X86_INS_MOVHPD,
    x86.X86_INS_MOVHPS,
    x86.X86_INS_MOVLHPS,
    x86.X86_INS_MOVLPD,
    x86.X86_INS_MOVLPS,
    x86.X86_INS_MOVMSKPD,
    x86.X86_INS_MOVMSKPS,
    x86.X86_INS_MOVNTDQA,
    x86.X86_INS_MOVNTDQ,
    x86.X86_INS_MOVNTI,
    x86.X86_INS_MOVNTPD,
    x86.X86_INS_MOVNTPS,
    x86.X86_INS_MOVNTSD,
    x86.X86_INS_MOVNTSS,
    x86.X86_INS_MOVSB,
    x86.X86_INS_MOVSD,
    x86.X86_INS_MOVSHDUP,
    x86.X86_INS_MOVSLDUP,
    x86.X86_INS_MOVSQ,
    x86.X86_INS_MOVSS,
    x86.X86_INS_MOVSW,
    x86.X86_INS_MOVSX,
    x86.X86_INS_MOVSXD,
    x86.X86_INS_MOVUPD,
    x86.X86_INS_MOVUPS,
    x86.X86_INS_MOVZX,
]

# BasicBlock end (cfg edge) unconditional
BB_END = [
    x86.X86_INS_RET,
    x86.X86_INS_RETF,
    x86.X86_INS_RETFQ,
    x86.X86_INS_IRET,
    x86.X86_INS_JMP,
    x86.X86_INS_CALL,
]

BB_COND = [
    x86.X86_INS_JAE,
    x86.X86_INS_JA,
    x86.X86_INS_JBE,
    x86.X86_INS_JB,
    x86.X86_INS_JCXZ,
    x86.X86_INS_JECXZ,
    x86.X86_INS_JE,
    x86.X86_INS_JGE,
    x86.X86_INS_JG,
    x86.X86_INS_JLE,
    x86.X86_INS_JL,
    x86.X86_INS_JNE,
    x86.X86_INS_JNO,
    x86.X86_INS_JNP,
    x86.X86_INS_JNS,
    x86.X86_INS_JO,
    x86.X86_INS_JP,
    x86.X86_INS_JRCXZ,
    x86.X86_INS_JS,
]

INSN_NOT_A_LOAD = [x86.X86_INS_LEA, x86.X86_INS_CMP, x86.X86_INS_NOP, x86.X86_INS_CMPSB]


def debug_print(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)


def print_register_state(register_state):
    pprint.pprint(
        {
            (REG_64_NAMES[k] if k in REG_64_NAMES else k): register_state[k]
            for k in register_state
        }
    )


def get_register_size(reg_id: int) -> int:
    if reg_id in REG_64:
        return 8
    if reg_id in REG_32:
        return 4
    if reg_id in REG_16:
        return 2  # Unknown register size
    if reg_id in REG_8:
        return 1
    return 0


def insn_ops(
    ins: CsInsn,
) -> tuple[Optional[x86.X86Op], Optional[x86.X86Op], Optional[x86.X86Op]]:
    src: Optional[x86.X86Op] = None
    dst: Optional[x86.X86Op] = None
    imm: Optional[x86.X86Op] = None
    n_ops = len(ins.operands)
    if n_ops == 1:
        (dst,) = ins.operands
    elif n_ops == 2:
        dst, src = ins.operands
    elif n_ops == 3:
        dst, src, imm = ins.operands
    return (dst, src, imm)


def op_is_mem(op: Optional[x86.X86Op]) -> bool:
    return op is not None and op.type == x86.X86_OP_MEM


def op_is_reg(op: Optional[x86.X86Op]) -> bool:
    return op is not None and op.type == x86.X86_OP_REG


def op_is_imm(op: Optional[x86.X86Op]) -> bool:
    return op is not None and op.type == x86.X86_OP_IMM


def to_str(ins: CsInsn) -> str:
    return f"{hex(ins.address)} {ins.mnemonic.ljust(10)} {ins.op_str.ljust(28)} {ins.bytes.hex()}"


class DummyExecutor:
    def map(self, *args, **kwargs):
        return map(*args, **kwargs)


class Job:
    def __init__(self, sect_off: int, elf_sh) -> None:
        self.sect_off: int = sect_off
        self.elf_sh = elf_sh


def reg_predictable(reg: RegisterState | None):
    return (reg is None) or reg.is_predictable()


def reg_attacker_ptr(reg: RegisterState | None):
    return (reg is not None) and reg.attacker_ptr


def reg_secret_ptr(reg: RegisterState | None):
    return (reg is not None) and reg.secret_ptr


def reg_secret(reg: RegisterState | None):
    return (reg is not None) and reg.secret


def reg_tainted(reg: RegisterState | None):
    return (reg is not None) and reg.tainted


def reg_combined_taint(reg1: RegisterState | None, reg2: RegisterState | None):
    return (reg_secret(reg1) and reg_attacker_ptr(reg2)) or (
        reg_secret(reg2) and reg_attacker_ptr(reg1)
    )


class Gadget:
    def __init__(self, md: Cs, state: "GadgetState", bytes: bytearray):
        self.start = state.va
        self.end = state.end_va
        self.bytes = bytes

        self.types = (
            ("f" if state.fr_possible else "")
            + ("p" if state.pp_possible else "")
            + ("b" if state.btb_possible else "")
            + ("j" if state.jop_possible else "")
        )

        # build assembly string
        self.asm = ""
        for ins in md.disasm(bytes, self.start):
            self.asm += "  " + to_str(ins) + "\n"
            if ins.address == self.end:
                break

    def __repr__(self):
        return f"Gadget({hex(self.start)} - {hex(self.end)},[{self.types}]) {{\n{self.asm}}}\n"


class GadgetState:
    def __init__(self, va: int) -> None:
        self.reset(va)

    def reset(self, va: int) -> None:
        self.va: int = va
        self.end_va: int = 0

        if TEST_MODE:
            self.initial_state = {
                x86.X86_REG_RBX: RegisterState(value_range=Range(0x1238)),
                x86.X86_REG_R12: RegisterState(value_range=Range(-139)),
                x86.X86_REG_R13: RegisterState(
                    mem_control=Range(8, 0x108),
                    attacker_ptr=True,
                ),
                x86.X86_REG_RSP: RegisterState(mem_control=Range(8, 0x88)),
            }
        else:
            self.initial_state = copy.deepcopy(INITIAL_REGISTER_STATE)
        self.register_state = self.initial_state
        self.fr_possible = False
        self.pp_possible = False
        self.btb_possible = False
        self.jop_possible = False

        debug_print("state reset")

        if DEBUG:
            print_register_state(self.register_state)

    def has_value(self):
        # check if we have gotten any futher than the initial state yet. if not, we might as well stop
        valuable = False
        for register in self.register_state:
            if (
                register not in self.initial_state
                and not self.register_state[register].is_reset()
            ):
                valuable = True
                break
            if register in self.initial_state and not self.initial_state[
                register
            ].superset_of(self.register_state[register]):
                valuable = True
                break
        return valuable

    def normalize_reg(self, reg) -> int:
        if reg in rregmap:
            return rregmap[reg]
        else:
            return reg

    def get_register(self, reg) -> RegisterState:
        reg = self.normalize_reg(reg)
        if reg == x86.X86_REG_INVALID:
            out = None
        elif reg in self.register_state:
            out = self.register_state[reg]
        else:
            out = self.reset_register(reg)
        return out

    def reset_register(self, reg) -> RegisterState:
        reg = self.normalize_reg(reg)
        out = RegisterState()
        self.register_state[reg] = out
        return out

    def mark_fr_possible(self):
        self.fr_possible = True
        debug_print("fr possible!")

    def mark_pp_possible(self):
        self.pp_possible = True
        debug_print("pp possible!")

    def mark_btb_possible(self):
        self.btb_possible = True
        debug_print("btb leak possible!")

    def mark_jop_possible(self):
        self.jop_possible = True
        debug_print("jop leak possible!")

    def is_jop_possible(self):
        # check that there is at least one secret register and one controlled register and they are not the same

        secret_reg_set = set()
        for reg in self.register_state:
            if reg_secret_ptr(self.register_state[reg]):
                secret_reg_set.add(reg)

        if len(secret_reg_set) == 0:
            # debug_print("nothing secret")
            return False

        controlled_reg_set = set()
        for reg in self.register_state:
            if reg_attacker_ptr(self.register_state[reg]):
                controlled_reg_set.add(reg)

        if len(controlled_reg_set) == 0:
            # debug_print("nothing controlled")
            return False

        debug_print(f"secret set: {secret_reg_set}")
        debug_print(f"controlled set: {controlled_reg_set}")

        if secret_reg_set == controlled_reg_set and len(secret_reg_set) == 1:
            return False

        return True

    def advance_mem_dst(self, dst):
        if not op_is_mem(dst):
            return

        debug_print("mem dest")
        index_reg = self.get_register(dst.mem.index)
        base_reg = self.get_register(dst.mem.base)

        if (
            (reg_tainted(index_reg) and reg_predictable(base_reg))
            or (reg_tainted(base_reg) and reg_predictable(index_reg))
            or reg_combined_taint(index_reg, base_reg)
        ):
            self.mark_fr_possible()

        if reg_secret(index_reg) or reg_secret(base_reg):
            self.mark_pp_possible()

        # propagate attacker
        # if base_reg.attacker_ptr or index_reg.attacker_ptr:
        # TODO: could mark some memory as controlled or maybe controlled here?
        # progress = True
        # pass

    def advance(self, insn):
        dst, src, imm = insn_ops(insn)
        progress = False

        # `xor reg, reg` resets the register to zero
        if (
            insn.id == x86.X86_INS_XOR
            and op_is_reg(src)
            and op_is_reg(dst)
            and src.reg == dst.reg
            and get_register_size(src.reg) == 8
        ):
            debug_print("xor zero register")
            reg = self.reset_register(src.reg)
            reg.value_range = Range(0, 0)
            return True

        # immediate propagation
        if op_is_imm(src) and op_is_reg(dst) and insn.id in ARITH_ADD:
            debug_print("imm_add")
            self.get_register(dst.reg).add(src.imm)
            return False
        if op_is_imm(src) and op_is_reg(dst) and insn.id in ARITH_SUB:
            debug_print("imm_sub")
            self.get_register(dst.reg).add(-src.imm)
            return False

        # special case for pop
        if insn.id == x86.X86_INS_POP:
            # pop always operate on the RSP
            rsp_reg = self.get_register(x86.X86_REG_RSP)
            # if we have control over the stack, we need to update the controlled range and
            # possibly the marking of the target register
            if op_is_reg(dst):
                dst_reg = self.reset_register(dst.reg)
                rsz = get_register_size(dst.reg)
                debug_print(f"pop to reg ({rsz})")
                # if we control something on the stack then we might control loaded data
                if (
                    rsp_reg.mem_control is not None
                    and rsp_reg.mem_control.disp_in_range(0)
                    and rsz == 8
                ):
                    debug_print("popping pointers")
                    dst_reg.attacker_ptr = True
                    dst_reg.secret_ptr = True

                # if the rsp is marked as a secret pointer we can also mark the loaded value as secret
                dst_reg.secret = rsp_reg.secret_ptr

                # push/pop moves the stack pointer, moving the area of control
                rsp_reg.add(rsz)

            # TODO could maybe add a controlled memory region to the destination register
            elif op_is_mem(dst):
                debug_print("pop to mem")
                self.advance_mem_dst(dst)
                rsp_reg.add(dst.size)

            # rsp could even be tainted in spec execution
            if rsp_reg.tainted:
                self.mark_fr_possible()
                return True

            return (rsp_reg.mem_control is not None) or rsp_reg.secret_ptr

        # special case for push
        if insn.id == x86.X86_INS_PUSH:
            # update the region of memory we control since we are storing to memory
            rsp_reg = self.get_register(x86.X86_REG_RSP)
            if op_is_reg(dst):
                rsz = get_register_size(dst.reg)
                rsp_reg.add(-rsz)

            if op_is_mem(dst):
                rsp_reg.add(-dst.size)

            # rsp could even be tainted in spec execution
            if rsp_reg.tainted:
                self.mark_fr_possible()
                return True

            return rsp_reg.mem_control is not None

        # arithmetic propagation
        if op_is_reg(src) and op_is_reg(dst) and insn.id in (ARITH_INS + LOGIC_INS):
            debug_print("arith")
            src_reg = self.get_register(src.reg)
            dst_reg = self.get_register(dst.reg)

            # heavy overapproximatin where we just propagate everything
            if not (src_reg.is_predictable() or dst_reg.is_predictable()):
                return False

            dst_reg.merge(src_reg)

            return True

        if op_is_mem(src) and op_is_reg(dst) and insn.id in [x86.X86_INS_LEA]:
            debug_print("lea")
            index_reg = self.get_register(dst.mem.index)
            base_reg = self.get_register(dst.mem.base)
            dst_reg = self.reset_register(dst.reg)

            dst_reg.merge(base_reg)
            dst_reg.merge(index_reg)
            if reg_combined_taint(index_reg, base_reg):
                dst_reg.tainted = True
            return True

        if op_is_imm(src) and op_is_reg(dst) and insn.id not in (ARITH_INS + LOGIC_INS):
            debug_print("imm reset")
            # propagating into any of our sets also clears
            self.reset_register(dst.reg)
            return True

        if insn.id in [x86.X86_INS_CALL, x86.X86_INS_JMP]:
            success = False

            ind_reg = None
            if op_is_reg(dst):
                debug_print("indirect jump to reg")
                ind_reg = self.get_register(dst.reg)
                if reg_tainted(ind_reg) or reg_secret(ind_reg):
                    self.mark_btb_possible()
                    success = True

            if op_is_mem(dst):
                debug_print("indirect jump to mem")
                ind_reg = self.get_register(dst.mem.base)
                if reg_tainted(ind_reg) or reg_secret(ind_reg):
                    self.mark_btb_possible()
                    success = True

            # check if there is:
            # - a controlled register
            # - a secret register
            if ind_reg and not reg_secret_ptr(ind_reg) and self.is_jop_possible():
                self.mark_jop_possible()
                success = True

            return success

        if op_is_reg(dst) and op_is_reg(src) and insn.id in MOV_INS:
            debug_print("mov reg")
            dst_reg = self.get_register(dst.reg)
            src_reg = self.get_register(src.reg)
            dst_reg.overwrite(src_reg)
            if get_register_size(dst.reg) != 8:
                dst_reg.attacker_ptr = False
                dst_reg.secret_ptr = False
            return not dst_reg.is_reset()

        # if op_is_reg(dst) and insn.id not in [x86.X86_INS_TEST, x86.X86_INS_CMP]:
        #     dst_reg = self.get_register(dst.reg)
        #     if op_is_reg(src):
        #         src_reg = self.get_register(src.reg)
        #         debug_print("primitive propagate reg")
        #         dst_reg.attacker_ptr |= src_reg.attacker_ptr
        #         dst_reg.secret_ptr |= src_reg.secret_ptr
        #         dst_reg.secret |= src_reg.secret
        #         dst_reg.tainted |= src_reg.tainted
        #         progress = True
        #         # TODO: propagate displacement?

        # memory propagation
        self.advance_mem_dst(dst)

        if op_is_mem(src) and insn.id not in INSN_NOT_A_LOAD:
            debug_print("mem src")
            index_reg: RegisterState = self.get_register(src.mem.index)
            base_reg: RegisterState = self.get_register(src.mem.base)
            debug_print("base", base_reg)
            debug_print("index", index_reg)

            # secret-dep memory dereference
            if (
                (reg_tainted(base_reg) and reg_predictable(index_reg))
                or (reg_tainted(index_reg) and reg_predictable(base_reg))
                or reg_combined_taint(index_reg, base_reg)
            ):
                self.fr_possible = True
                debug_print("fr possible!")
                progress = True
            if (reg_secret(base_reg) and reg_predictable(index_reg)) or (
                reg_secret(index_reg) and reg_predictable(base_reg)
            ):
                self.pp_possible = True
                progress = True
                debug_print("pp possible!")

            if op_is_reg(dst):
                debug_print("oh load!")
                dst_new = self.reset_register(dst.reg)

                # controlled pointer dereference
                disp = src.mem.disp
                scale = src.mem.scale

                # check for interesting pointer loading
                if get_register_size(dst.reg) == 8:
                    debug_print(
                        f"ptr load control={reg_attacker_ptr(base_reg)}, predict={reg_predictable(index_reg)}"
                    )
                    if reg_attacker_ptr(base_reg) and reg_predictable(index_reg):
                        #     and base_reg.mem_control.disp_in_range(
                        #     disp + index_reg.value_range * scale
                        # ):
                        debug_print("base controlled")
                        dst_new.attacker_ptr = True
                        dst_new.secret_ptr = True
                        progress = True
                    if (
                        reg_attacker_ptr(index_reg)
                        and reg_predictable(base_reg)
                        and scale == 1
                    ):
                        # and base_reg.mem_control.disp_in_range(
                        #     disp + base_reg.value_range
                        # )
                        debug_print("index controlled")
                        dst_new.attacker_ptr = True
                        dst_new.secret_ptr = True
                        progress = True

                # secret ptr dereference
                if (
                    reg_secret_ptr(base_reg) or reg_secret_ptr(index_reg)
                ) and get_register_size(dst.reg) in SECRET_LOAD_SIZES:
                    debug_print("secret loaded")
                    dst_new.secret = True
                    progress = True
        return progress


def op_to_str(op):
    if op_is_reg(op):
        return f"reg({op.reg})"
    elif op_is_mem(op):
        return f"mem({op.mem})"
    elif op_is_imm(op):
        return f"imm({op.imm})"
    else:
        return "None"


def scan(md: Cs, code: bytearray, va: int) -> Optional[GadgetState]:
    g = GadgetState(va)
    it: Generator[CsInsn] = md.disasm(code, va, count=MAX_GADGET_SIZE)
    for insn_count, insn in enumerate(it):
        debug_print(insn)
        # dst, src, imm = insn_ops(insn)
        # debug_print(f"dst: {op_to_str(dst)}, src: {op_to_str(src)}, imm: {imm}")
        # instruction that we consider "ending" our gadget
        if insn.id == x86.X86_INS_INT3:
            debug_print("interrupt")
            break
        if insn.prefix[0] != 0 or insn.id == x86.X86_INS_NOP:
            if insn_count == 0:
                break
            continue

        # insn info
        progress = g.advance(insn)
        if DEBUG:
            print_register_state(g.register_state)

        if (ENABLE_FR and g.fr_possible) or (ENABLE_BTB and g.btb_possible):
            g.end_va = insn.address
            return Gadget(md, g, code)

        if insn.id in BB_END:
            debug_print("end of basic block")
            if ENABLE_DUMB and g.is_jop_possible():
                g.end_va = insn.address
                return Gadget(md, g, code)
            break
        if insn_count == 0 and not progress:
            debug_print("no progress")
            break
        # if not g.has_value():
        #     debug_print("state has no value")
        #     break
    if ENABLE_PP and g.pp_possible:
        g.end_va = insn.address
        return Gadget(md, g, code)

    if ENABLE_JOP and g.jop_possible:
        g.end_va = insn.address
        return Gadget(md, g, code)

    debug_print("failed")
    return None


def scan_job(data):
    job, blob = data

    md: Cs = Cs(CS_ARCH_X86, CS_MODE_64 | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    found_gadgets = []
    last_found = None  # we want to avoid printing the same gadget multiple times

    for off in range(job.sect_off, min(job.sect_off + JOB_CHUNK, job.elf_sh.sh_size)):
        va = job.elf_sh.sh_addr + off
        codeview: bytearray = blob[off : off + CODE_VIEW_SIZE]

        # check the current code view for gadgets
        gadg: Optional[Gadget] = scan(md, codeview, va)
        if gadg is not None:
            # we assume gadgets are distinct iff they have different ending addresses (not true)
            if last_found and last_found.end != gadg.end:
                found_gadgets.append(last_found)
            last_found = gadg

    if last_found is not None:
        found_gadgets.append(last_found)

    return found_gadgets


def scan_binary(
    executor: ThreadPoolExecutor | DummyExecutor,
    binary_path,
    output_file,
    start_va=None,
):
    # print header for the binary in the results
    print(f"scanning {binary_path}")
    output_file.write("-" * 80 + "\n")
    output_file.write(f"scanning {binary_path}\n")
    output_file.write("-" * 80 + "\n")
    output_file.flush()

    with open(binary_path, "rb") as text:
        # load all the executable sections from the binary
        elf_file: ELFFile = ELFFile(text)
        exec_sections: list[sections.Section] = [
            s
            for s in elf_file.iter_sections()
            if s.header.sh_flags & SH_FLAGS.SHF_EXECINSTR
        ]

        # schedule all sections for analysis
        section_runs = {}
        for i, section in enumerate(exec_sections):
            header = section.header
            section_start_va = max(header.sh_addr, start_va or header.sh_addr)

            # load the section binary data
            text.seek(header.sh_offset)
            blob = bytearray(text.read(header.sh_size))

            # split the work into chunks for better parallelism
            jobs = []
            for sect_off in range(
                section_start_va - header.sh_addr, header.sh_size, JOB_CHUNK
            ):
                jobs.append((Job(sect_off, header), blob))

            results = executor.map(scan_job, jobs)
            section_runs[i] = results, len(jobs)

    # accumulate the results
    gadget_count = 0
    for i in section_runs:
        section = exec_sections[i]
        header = section.header
        print(
            "----Section: %012lx -- %012lx"
            % (header.sh_addr, header.sh_addr + header.sh_size)
        )
        results, results_len = section_runs[i]

        with alive_bar(results_len) as bar:
            for res in results:
                for gadget in res:
                    print(f"{gadget.start} - {gadget.end}: {gadget.types}")
                    output_file.write(repr(gadget))
                    output_file.flush()
                    gadget_count += 1
                bar()

    return gadget_count


def main():
    binary_path = sys.argv[1]
    start_va = None
    if len(sys.argv) > 2:
        start_va = int(sys.argv[2], 16)

    # parallelize work for SPEED
    if TEST_MODE or DEBUG:
        executor = DummyExecutor()
    else:
        executor = ThreadPoolExecutor(max_workers=THREADS)

    # write gadgets to a file
    gadget_count = 0
    with open("gadget.txt", "w+", encoding="utf-8") as output_file:
        # analyze the main binary
        gadget_count += scan_binary(
            executor, binary_path, output_file, start_va=start_va
        )

        if TEST_MODE:
            if gadget_count == 0:
                sys.exit(1)
            return

        if not ENABLE_LIBRARIES:
            return

        # look dynamic libraries that are loaded
        libraries_raw = check_output(args=["/usr/bin/ldd", binary_path]).decode("utf-8")
        libraries_raw = libraries_raw.split("\n")
        for lib_raw in libraries_raw:
            match = re.match(LIB_REGEX, lib_raw)
            if match is not None:
                lib_path = match.group("path")
                # scan the library
                gadget_count += scan_binary(executor, lib_path, output_file)


if __name__ == "__main__":
    main()
