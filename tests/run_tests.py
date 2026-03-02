import subprocess
import os
import re
import sys
import time

# eBPF Constants (Mirroring include/ebpf.h)
BPF_LD    = 0x00
BPF_ALU   = 0x04
BPF_JMP   = 0x05
BPF_ALU64 = 0x07

BPF_K     = 0x00
BPF_X     = 0x08

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
BPF_EXIT  = 0x90

# Jump Opcodes
BPF_JA    = 0x00
BPF_JEQ   = 0x10
BPF_JGT   = 0x20
BPF_JGE   = 0x30
BPF_JSET  = 0x40
BPF_JNE   = 0x50
BPF_JSGT  = 0x60
BPF_JSGE  = 0x70
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

    success = runner.run_all()
    sys.exit(0 if success else 1)
