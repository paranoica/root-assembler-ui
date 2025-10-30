# region: imports
import json
import logging
import asyncio
import websockets

from capstone import *
from keystone import *

from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.mips_const import *
# endregion

# region: override default variables
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger("root-assembler-backend")

ARCHITECTURES = {
    "x86_64": {
        "cs": (CS_ARCH_X86, CS_MODE_64),
        "ks": (KS_ARCH_X86, KS_MODE_64),
        "uc": (UC_ARCH_X86, UC_MODE_64),
        "regs": [register for register in range(UC_X86_REG_XMM0, UC_X86_REG_XMM0 + 16)] + [
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
            UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
            UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
            UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
            UC_X86_REG_RIP, UC_X86_REG_EFLAGS
        ],
        "reg_names": [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "rip", "eflags"
        ]
    },
    "arm": {
        "cs": (CS_ARCH_ARM, CS_MODE_ARM),
        "ks": (KS_ARCH_ARM, KS_MODE_ARM),
        "uc": (UC_ARCH_ARM, UC_MODE_ARM),
        "regs": [
            UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3,
            UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7,
            UC_ARM_REG_R8, UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
            UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_LR, UC_ARM_REG_PC,
            UC_ARM_REG_CPSR
        ],
        "reg_names": [
            "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12", "sp", "lr", "pc",
            "cpsr"
        ]
    },
    "mips": {
        "cs": (CS_ARCH_MIPS, CS_MODE_MIPS32),
        "ks": (KS_ARCH_MIPS, KS_MODE_MIPS32),
        "uc": (UC_ARCH_MIPS, UC_MODE_MIPS32),
        "regs": [
            UC_MIPS_REG_0, UC_MIPS_REG_1, UC_MIPS_REG_2, UC_MIPS_REG_3,
            UC_MIPS_REG_4, UC_MIPS_REG_5, UC_MIPS_REG_6, UC_MIPS_REG_7,
            UC_MIPS_REG_8, UC_MIPS_REG_9, UC_MIPS_REG_10, UC_MIPS_REG_11,
            UC_MIPS_REG_12, UC_MIPS_REG_13, UC_MIPS_REG_14, UC_MIPS_REG_15,
            UC_MIPS_REG_PC
        ],
        "reg_names": [
            "zero", "at", "v0", "v1", "a0", "a1", "a2", "a3",
            "t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7",
            "pc"
        ]
    }
}
# endregion

# region: create emulator class
class Emulator:
    def __init__(self, arch):
        self.arch = ARCHITECTURES[arch]
        self.memcl = Uc(self.arch["uc"][0], self.arch["uc"][1])

        self.memory_base = 0x400000
        self.memory_size = 2 * 1024 * 1024

        self.stack_size = 2 * 1024 * 1024
        self.stack_base = self.memory_base + self.memory_size + self.stack_size

        self.memcl.mem_map(self.memory_base, self.memory_size)
        self.memcl.mem_map(self.memory_base + self.memory_size, self.stack_size)

        self.reset_registration_states()

    def get_registration_state(self):
        return {name: self.memcl.reg_read(reg) for name, reg in zip(self.arch["reg_names"], self.arch["regs"])}

    def reset_registration_states(self):
        for reg in self.arch["regs"]:
            self.memcl.reg_write(reg, 0x0)

        if "x86_64" in self.arch["uc"]:
            self.memcl.reg_write(UC_X86_REG_RSP, self.stack_base)

    def emulate(self, code):
        self.memcl.mem_write(self.memory_base, code)

        try:
            self.memcl.emu_start(self.memory_base, self.memory_base + len(code))
        except UcError as e:
            logger.error(f"client got an emulation error at initialization: {e}!")
            raise

emulators = {arch: Emulator(arch) for arch in ARCHITECTURES}
# endregion

# region: assembly auxiliary functions
def dissamble_and_emulate_observant_code(code, arch, emul):
    try:
        if isinstance(code, str):
            code = bytes.fromhex(code.replace(" ", ""))

        mdc = Cs(*ARCHITECTURES[arch]["cs"])
        eml = emulators[arch]
        dsm = []

        if emul:
            eml.reset_registration_states()
            registration_initial_state = eml.get_registration_state()
        else:
            registration_initial_state = None

        for i in mdc.disasm(code, eml.memory_base):
            if emul:
                before_registration_state = eml.get_registration_state()

                try:
                    eml.emulate(bytes(i.bytes))
                except UcError as e:
                    logger.error(f"client got an emulation error at instruction {i.mnemonic} {i.op_str}: {e}!")
                    raise ValueError(f"Client got an emulation error: {e}!")

                after_registration_state = eml.get_registration_state()
            else:
                before_registration_state = after_registration_state = None

            dsm.append({
                "address": f"0x{i.address:x}",
                "mnemonic": i.mnemonic,

                "op_str": i.op_str,
                "bytes": " ".join([f"{b:02x}" for b in i.bytes]),

                "after": after_registration_state,
                "before": before_registration_state
            })

        return {
            "instructions": dsm,
            "initial_state": registration_initial_state
        }
    except CsError as e:
        raise ValueError(f"Client got a disassembly error: {e}!")
    
def assemble_and_emulate_observant_code(code, arch, emul):
    try:
        ksc = Ks(*ARCHITECTURES[arch]["ks"])
        encoding, _ = ksc.asm(code)

        if not encoding:
            raise ValueError(f"Client failed to assemble observant code: {e}!")
        
        return dissamble_and_emulate_observant_code(bytes(encoding), arch, emul)
    except KsError as e:
        raise ValueError(f"Client got a assembly error: {e}!")
# endregion

# region: assembly executive functions
def detect_input_type(code):
    if all(c in "0123456789abcdefABCDEF \n" for c in code.strip()):
        if any(len(part.strip()) > 2 for part in code.split()):
            return "hex"
        else:
            return "shellcode"
    else:
        "asm"

def analyze_code(code, arch, emul):
    input_type = detect_input_type(code)

    if input_type == "hex":
        code = bytes.fromhex(code.replace("0x", "").replace(" ", "").replace("\n", ""))
        return dissamble_and_emulate_observant_code(code, arch, emul)
    elif input_type == "shellcode":
        code = bytes.fromhex(code.replace("\\x", "").replace("0x", "").replace(",", "").replace(" ", "").replace("\n", ""))
        return dissamble_and_emulate_observant_code(code, arch, emul)
    else:
        return assemble_and_emulate_observant_code(code, arch, emul)
# endregion

# region: client <-> server communcation
async def process_client_messages(websocket, path):
    logger.info("New client has been connected!")

    try:
        async for message in websocket:
            logger.debug(f"Received message from client: {message}")

            try:
                data = json.loads(message)
                result = analyze_code(data["code"], data.get("architecture", "x86_64"), data.get("emulationEnabled", True))

                await websocket.send(json.dumps({"result": result}))
            except json.JSONDecodeError as e:
                logger.error(f"client got a JSON-decode error: {e}!")
                await websocket.send(json.dumps({"error": "Invalid JSON"}))
            except ValueError as e:
                logger.error(f"client got a value error: {e}!")
                await websocket.send(json.dumps({"error": str(e)}))
            except Exception as e:
                logger.error(f"client got an unxpected error: {e}!")
                await websocket.send(json.dumps({"error": f"Server error: {str(e)}"}))
    except websockets.exceptions.ConnectionClosed:
        logger.info("client has been disconnected!")

async def provided_task_connections(websocket, path):
    async for message in websocket:
        await asyncio.create_task(process_client_messages(websocket, message))
# endregion

# region: provide initialization
async def main():
    server = await websockets.serve(provided_task_connections, "localhost", 5000)
    logger.info("Server has been started on http://localhost:5000/")

    await server.wait_closed()

if __name__ == "__main__":
    asyncio.run(main())
# endregion