import subprocess
import os
import re
import sys
import time

# eBPF Constants (Mirroring include/ebpf.h)
BPF_LD    = 0x00
BPF_LDX   = 0x01
BPF_ST    = 0x02
BPF_STX   = 0x03
BPF_ALU   = 0x04
BPF_JMP   = 0x05
BPF_JMP32 = 0x06
BPF_ALU64 = 0x07

BPF_K     = 0x00
BPF_X     = 0x08

# Size modifiers
BPF_W     = 0x00
BPF_H     = 0x08
BPF_B     = 0x10
BPF_DW    = 0x18

# Mode modifiers
BPF_IMM   = 0x00
BPF_ABS   = 0x20
BPF_IND   = 0x40
BPF_MEM   = 0x60
BPF_ATOMIC = 0xc0

# Atomic ops
BPF_FETCH = 0x01

BPF_ADD   = 0x00
BPF_SUB   = 0x10
BPF_MUL   = 0x20
BPF_DIV   = 0x30
BPF_OR    = 0x40
BPF_AND   = 0x50
BPF_LSH   = 0x60
BPF_RSH   = 0x70
BPF_NEG   = 0x80
BPF_MOD   = 0x90
BPF_XOR   = 0xa0
BPF_MOV   = 0xb0
BPF_ARSH  = 0xc0
BPF_END   = 0xd0
BPF_EXIT  = 0x90

# Endianness
BPF_TO_LE = 0x00
BPF_TO_BE = 0x08

# Jump Opcodes
BPF_JA    = 0x00
BPF_JEQ   = 0x10
BPF_JGT   = 0x20
BPF_JGE   = 0x30
BPF_JSET  = 0x40
BPF_JNE   = 0x50
BPF_JSGT  = 0x60
BPF_JSGE  = 0x70
BPF_CALL  = 0x80
BPF_JLT   = 0xa0
BPF_JLE   = 0xb0
BPF_JSLT  = 0xc0
BPF_JSLE  = 0xd0

class TestRunner:
    def __init__(self):
        self.tests = []

    def add_test(self, name, prog, expected_result):
        self.tests.append({
            "name": name,
            "prog": prog,
            "expected": expected_result
        })

    def generate_header(self, prog):
        with open("tests/test_case.h", "w") as f:
            f.write('#include "ebpf.h"\n\n')
            f.write('struct ebpf_inst test_prog[] = {\n')
            for inst in prog:
                f.write(f'    {{ {inst["op"]}, {inst["dst"]}, {inst["src"]}, {inst["off"]}, {inst["imm"]} }},\n')
            f.write('};\n')

    def run_qemu(self):
        # Build the project with the test runner macro
        cmd_build = 'make clean && make CFLAGS="-march=rv64g -mabi=lp64 -mcmodel=medany -Wall -O0 -g -ffreestanding -nostdlib -Iinclude -Itests -DTEST_RUNNER"'
        result = subprocess.run(cmd_build, shell=True, capture_output=True, text=True)
        if result.returncode != 0:
            print(f"Build Failed:\n{result.stderr}")
            return None

        # Run QEMU
        cmd_qemu = "qemu-system-riscv64 -machine virt -bios none -kernel firmware.elf -nographic"
        try:
            # We use a timeout to prevent hanging if JIT fails or infinite loop
            proc = subprocess.Popen(cmd_qemu, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = proc.communicate(timeout=5)
            return stdout
        except subprocess.TimeoutExpired:
            proc.kill()
            return "TIMEOUT"
        except Exception as e:
            return str(e)

    def extract_result(self, output):
        match = re.search(r">>> JIT EXECUTION RESULT: (\d+) <<<", output)
        if match:
            return int(match.group(1))
        return None

    def run_all(self):
        passed = 0
        total = len(self.tests)

        print(f"Running {total} tests...\n")

        for test in self.tests:
            print(f"Test: {test['name']}... ", end="", flush=True)
            self.generate_header(test['prog'])
            output = self.run_qemu()
            
            if output == "TIMEOUT":
                print("FAILED (Timeout)")
                continue
            if output is None:
                print("FAILED (Build failed)")
                continue
            
            result = self.extract_result(output)
            if result == test['expected']:
                print("PASSED")
                passed += 1
            else:
                print(f"FAILED (Expected {test['expected']}, got {result})")
                if result is None:
                    print(f"Debug Output:\n{output}")

        print(f"\nResults: {passed}/{total} tests passed.")
        return passed == total

if __name__ == "__main__":
    runner = TestRunner()

    # Test 1: Simple MOV and ADD (64-bit)
    runner.add_test("ALU64_ADD_IMM", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 100},
        {"op": BPF_ALU64 | BPF_ADD | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 50},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 150)

    # Test 2: Multiplication
    runner.add_test("ALU64_MUL_IMM", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 7},
        {"op": BPF_ALU64 | BPF_MUL | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 6},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 42)

    # Test 3: Bitwise shifts
    runner.add_test("ALU64_LSH_IMM", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},
        {"op": BPF_ALU64 | BPF_LSH | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 10},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 1024)

    # Test 4: Register-to-Register MOV and ADD
    runner.add_test("ALU64_REG_MOV_ADD", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 20},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 2, "src": 0, "off": 0, "imm": 30},
        {"op": BPF_ALU64 | BPF_MOV | BPF_X, "dst": 0, "src": 1, "off": 0, "imm": 0},
        {"op": BPF_ALU64 | BPF_ADD | BPF_X, "dst": 0, "src": 2, "off": 0, "imm": 0},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 50)

    # Test 5: Subtraction (handling Path C in jit.c)
    runner.add_test("ALU64_SUB_IMM", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 100},
        {"op": BPF_ALU64 | BPF_SUB | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 40},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 60)

    # Test 6: Simple Jump Always
    runner.add_test("JMP_JA", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},
        {"op": BPF_JMP | BPF_JA, "dst": 0, "src": 0, "off": 1, "imm": 0},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 2},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 1)

    # Test 7: Jump Equal (True)
    runner.add_test("JMP_JEQ_K_TRUE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 10},    # 0: R1 = 10
        {"op": BPF_JMP | BPF_JEQ | BPF_K, "dst": 1, "src": 0, "off": 2, "imm": 10},   # 1: if R1 == 10 goto 4
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 2},    # 2: R0 = 2
        {"op": BPF_JMP | BPF_JA, "dst": 0, "src": 0, "off": 1, "imm": 0},            # 3: goto 5
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},    # 4: R0 = 1
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},          # 5: exit
    ], 1)

    # Test 8: Jump Equal (False)
    runner.add_test("JMP_JEQ_K_FALSE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 10},    # 0: R1 = 10
        {"op": BPF_JMP | BPF_JEQ | BPF_K, "dst": 1, "src": 0, "off": 2, "imm": 20},   # 1: if R1 == 20 goto 4
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 2},    # 2: R0 = 2
        {"op": BPF_JMP | BPF_JA, "dst": 0, "src": 0, "off": 1, "imm": 0},            # 3: goto 5
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},    # 4: R0 = 1
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},          # 5: exit
    ], 2)

    # Test 9: Register comparison (JGT)
    runner.add_test("JMP_JGT_X_TRUE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 20},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 2, "src": 0, "off": 0, "imm": 10},
        {"op": BPF_JMP | BPF_JGT | BPF_X, "dst": 1, "src": 2, "off": 1, "imm": 0},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 2},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 3},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 3)

    # Test 10: Bitwise AND, OR, XOR
    runner.add_test("ALU64_BITWISE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0xF0},
        {"op": BPF_ALU64 | BPF_AND | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0x33}, # 0xF0 & 0x33 = 0x30
        {"op": BPF_ALU64 | BPF_OR  | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0x0C}, # 0x30 | 0x0C = 0x3C
        {"op": BPF_ALU64 | BPF_XOR | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0xFF}, # 0x3C ^ 0xFF = 0xC3
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0xC3)

    # Test 11: Large Immediate (>12 bits)
    runner.add_test("ALU64_LARGE_IMM", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0x12345678},
        {"op": BPF_ALU64 | BPF_ADD | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0x12345679)

    # Test 12: JMP_JNE (True)
    runner.add_test("JMP_JNE_K_TRUE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},
        {"op": BPF_JMP | BPF_JNE | BPF_K, "dst": 0, "src": 0, "off": 1, "imm": 2},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 3},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 1)

    # Test 13: JMP_JGE (Unsigned)
    runner.add_test("JMP_JGE_K_TRUE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 10},
        {"op": BPF_JMP | BPF_JGE | BPF_K, "dst": 0, "src": 0, "off": 1, "imm": 5},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 10)

    # Test 14: JMP_JSGT (Signed comparison)
    runner.add_test("JMP_JSGT_K_TRUE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": -1},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 2, "src": 0, "off": 0, "imm": -5},
        {"op": BPF_JMP | BPF_JSGT | BPF_X, "dst": 1, "src": 2, "off": 1, "imm": 0},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 42},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 42)

    # Test 15: Backward Jump (Loop-like)
    runner.add_test("JMP_BACKWARD", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 5},    # R1 = 5
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0},    # R0 = 0
        {"op": BPF_ALU64 | BPF_ADD | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},    # R0 += 1 (Target)
        {"op": BPF_ALU64 | BPF_SUB | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 1},    # R1 -= 1
        {"op": BPF_JMP | BPF_JGT | BPF_K, "dst": 1, "src": 0, "off": -3, "imm": 0},   # if R1 > 0 goto Target
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},          # exit
    ], 5)

    # Test 16: ALU32 truncation
    runner.add_test("ALU32_ADD_K", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": -1},   # R0 = 0xFFFFFFFFFFFFFFFF
        {"op": BPF_ALU   | BPF_ADD | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},    # R0 = (u32)R0 + 1 = 0
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0)

    # Test 17: JMP_JSET (True)
    runner.add_test("JMP_JSET_K_TRUE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 0x5},
        {"op": BPF_JMP | BPF_JSET | BPF_K, "dst": 1, "src": 0, "off": 1, "imm": 0x1},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 42},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 42)

    # Test 18: JMP_JLT (Unsigned)
    runner.add_test("JMP_JLT_K_TRUE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 5},
        {"op": BPF_JMP | BPF_JLT | BPF_K, "dst": 1, "src": 0, "off": 1, "imm": 10},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 1)

    # Test 19: JMP_JSLT (Signed)
    runner.add_test("JMP_JSLT_K_TRUE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": -10},
        {"op": BPF_JMP | BPF_JSLT | BPF_K, "dst": 1, "src": 0, "off": 1, "imm": -5},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 1)

    # Test 21: JMP32_JEQ (True, ignoring upper 32 bits)
    runner.add_test("JMP32_JEQ_K_TRUE", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 0x1}, # Load 1
        # Shift left by 32 to put 1 in upper bits, keeping 0 in lower 32
        {"op": BPF_ALU64 | BPF_LSH | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 32},  # R1 = 0x100000000
        {"op": BPF_JMP32 | BPF_JEQ | BPF_K, "dst": 1, "src": 0, "off": 1, "imm": 0},   # if (u32)R1 == 0 goto 4
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 42},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 42)

    # Test 22: STX and LDX (Double Word)
    runner.add_test("MEM_STX_LDX_DW", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 0x12345678},
        {"op": BPF_STX | BPF_DW | BPF_MEM,  "dst": 10, "src": 1, "off": -8, "imm": 0},    # *(u64*)(R10 - 8) = R1
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 0},       # Clear R1
        {"op": BPF_LDX | BPF_DW | BPF_MEM,  "dst": 0, "src": 10, "off": -8, "imm": 0},    # R0 = *(u64*)(R10 - 8)
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0x12345678)

    # Test 23: ST (Immediate store)
    runner.add_test("MEM_ST_W", [
        {"op": BPF_ST | BPF_W | BPF_MEM, "dst": 10, "src": 0, "off": -4, "imm": 0xABCDE}, # *(u32*)(R10 - 4) = 0xABCDE
        {"op": BPF_LDX | BPF_W | BPF_MEM, "dst": 0, "src": 10, "off": -4, "imm": 0},      # R0 = *(u32*)(R10 - 4)
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0xABCDE)

    # Test 25: Context Parameter (R1)
    # The runner in main.c passes &ctx_data (where ctx_data = 100)
    runner.add_test("CTX_LOAD_R1", [
        {"op": BPF_LDX | BPF_DW | BPF_MEM, "dst": 0, "src": 1, "off": 0, "imm": 0},    # R0 = *(u64*)R1
        {"op": BPF_ALU64 | BPF_ADD | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 10},  # R0 += 10
        {"op": BPF_JMP | BPF_EXIT,         "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 110)

    # Test 26: BPF_CALL (uart_print_int)
    runner.add_test("JMP_CALL_UART_PRINT_INT", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 1234},
        {"op": BPF_JMP | BPF_CALL,         "dst": 0, "src": 0, "off": 0, "imm": 2},    # call uart_print_int
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1234}, # R0 = 1234
        {"op": BPF_JMP | BPF_EXIT,         "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 1234)

    # Test 27: Atomic ADD
    runner.add_test("MEM_ATOMIC_ADD", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 1, "src": 0, "off": 0, "imm": 10},
        {"op": BPF_STX | BPF_DW | BPF_MEM,  "dst": 10, "src": 1, "off": -8, "imm": 0},    # *(u64*)(R10 - 8) = 10
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 2, "src": 0, "off": 0, "imm": 5},
        {"op": BPF_STX | BPF_DW | BPF_ATOMIC, "dst": 10, "src": 2, "off": -8, "imm": BPF_ADD}, # *(u64*)(R10 - 8) += 5
        {"op": BPF_LDX | BPF_DW | BPF_MEM,  "dst": 0, "src": 10, "off": -8, "imm": 0},    # R0 = *(u64*)(R10 - 8)
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 15)

    # Test 28: LD_IMM64 (16-byte instruction)
    runner.add_test("LD_IMM64", [
        {"op": BPF_LD | BPF_DW | BPF_IMM, "dst": 0, "src": 0, "off": 0, "imm": 0x12345678},
        {"op": 0,                         "dst": 0, "src": 0, "off": 0, "imm": 0xDEADBEEF},
        {"op": BPF_JMP | BPF_EXIT,         "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0xDEADBEEF12345678)

    # Test 29: BPF_END (TO_LE 16-bit)
    runner.add_test("ALU_END_TO_LE_16", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0x12345678},
        {"op": BPF_ALU | BPF_END | BPF_TO_LE, "dst": 0, "src": 0, "off": 0, "imm": 16},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0x5678)

    # Test 30: BPF_END (TO_LE 32-bit)
    runner.add_test("ALU_END_TO_LE_32", [
        {"op": BPF_LD | BPF_DW | BPF_IMM, "dst": 0, "src": 0, "off": 0, "imm": 0xABCDEF01},
        {"op": 0,                         "dst": 0, "src": 0, "off": 0, "imm": 0x12345678},
        {"op": BPF_ALU | BPF_END | BPF_TO_LE, "dst": 0, "src": 0, "off": 0, "imm": 32},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0xABCDEF01)

    # Test 31: BPF_END (TO_BE 16-bit)
    runner.add_test("ALU_END_TO_BE_16", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0x1234},
        {"op": BPF_ALU | BPF_END | BPF_TO_BE, "dst": 0, "src": 0, "off": 0, "imm": 16},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0x3412)

    # Test 32: BPF_END (TO_BE 32-bit)
    runner.add_test("ALU_END_TO_BE_32", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 0x12345678},
        {"op": BPF_ALU | BPF_END | BPF_TO_BE, "dst": 0, "src": 0, "off": 0, "imm": 32},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0x78563412)

    # Test 33: BPF_END (TO_BE 64-bit)
    runner.add_test("ALU_END_TO_BE_64", [
        {"op": BPF_LD | BPF_DW | BPF_IMM, "dst": 0, "src": 0, "off": 0, "imm": 0x11223344},
        {"op": 0,                         "dst": 0, "src": 0, "off": 0, "imm": 0x55667788},
        {"op": BPF_ALU | BPF_END | BPF_TO_BE, "dst": 0, "src": 0, "off": 0, "imm": 64},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 0x4433221188776655)

    # Bug Reproduction: BPF_JMP32 | BPF_JA should NOT act as an unconditional jump anymore
    # Because we fixed it to only work for BPF_JMP class.
    # So BPF_JMP32 | BPF_JA should now fall through to emit_jmp,
    # which will then hit the default switch case (doing nothing for JA)
    # Wait, if BPF_JMP32 | BPF_JA falls through to emit_jmp,
    # emit_jmp checks if (BPF_OP(op) == BPF_JA) and emits a jump.
    # So it still works as JA. 
    # The user said: "BPF_JA is only available for BPF_JMP (64bit), not BPF_JMP32"
    # So I should probably make emit_jmp ONLY handle BPF_JA if it's NOT jmp32.

    # Let's see what happens with current implementation.
    runner.add_test("BUG_JMP32_JA_DISABLED", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 1},
        {"op": BPF_JMP32 | BPF_JA, "dst": 0, "src": 0, "off": 1, "imm": 0},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 2},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 2) # Now expecting 2 because JA should be ignored for JMP32

    # Bug Reproduction: BPF_JMP32 | BPF_EXIT should NOT act as exit anymore
    runner.add_test("BUG_JMP32_EXIT_DISABLED", [
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 42},
        {"op": BPF_JMP32 | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
        {"op": BPF_ALU64 | BPF_MOV | BPF_K, "dst": 0, "src": 0, "off": 0, "imm": 43},
        {"op": BPF_JMP | BPF_EXIT, "dst": 0, "src": 0, "off": 0, "imm": 0},
    ], 43) # Now expecting 43 because EXIT should be ignored for JMP32

    success = runner.run_all()
    sys.exit(0 if success else 1)
