#!/usr/bin/env python
# Sample code for ARM of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>
# Python sample ported by Loi Anh Tuan <loianhtuan@gmail.com>

from __future__ import print_function
from unicorn import *
import random
from unicorn.arm_const import *
import serial
import struct
RAM_SIZE = 0x400000;
TEXT_START_ADDRESS = 0x08000;
MAIN_ADDRESS = 0x0800c | 1;
EXIT_ADDRESS = 0x8014;
STACK_ADDRESS = 0x200000;
INPUT_ADDRESS = 0x380000;
ser = None
findBlocks = {}

def gather_data():
    global ser
    if not ser:
        ser = serial.Serial('/dev/ttyACM0')
    count = 0
    ans = b''
    while count < 10:
        count += 1
        dat = ser.read(26)
        ans = ans + dat[6:22]
    #print(ans)
    return ans

def hook_block(uc, address, size, user_data):
    global findBlocks
    if address not in findBlocks:
        findBlocks[address] = 1
        print(">>> Tracing basic block at 0x%x, block size = 0x%x" %(address, size))

def test_thumb():
    print("Measure Heartrate")
    try:
        fp = open('prog.bin', 'rb')

        prog = fp.read()

        # Initialize emulator in thumb mode
        mu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)

        # map 2MB memory for this emulation
        mu.mem_map(0, RAM_SIZE)

        # write machine code to be emulated to memory
        mu.mem_write(TEXT_START_ADDRESS, prog)

        # initialize machine registers
        tmp_val = mu.reg_read(UC_ARM_REG_C1_C0_2);
        tmp_val = tmp_val | (0xf << 20);
        mu.reg_write(UC_ARM_REG_C1_C0_2, tmp_val);
        mu.reg_write(UC_ARM_REG_D16, 0xffff1111);
        mu.reg_write(UC_ARM_REG_FPEXC, 0x40000000);
        
        #mu.hook_add(UC_HOOK_BLOCK, hook_block)

        while True:
            rawInput = gather_data()
            mu.mem_write(INPUT_ADDRESS, rawInput)
            mu.reg_write(UC_ARM_REG_SP, STACK_ADDRESS);
            mu.reg_write(UC_ARM_REG_LR, MAIN_ADDRESS);
            # emulate machine code in infinite time
            # Note we start at ADDRESS | 1 to indicate THUMB mode.
            mu.emu_start(MAIN_ADDRESS, EXIT_ADDRESS)

            # now print out some registers
            resp = mu.mem_read(0x3F0000, 16)
            resp = struct.unpack('IIII', resp)
            if resp[0] == 48 or resp[0] == 0:
                print("  Heartrate: %d Trust Level: %d Signal: %d  " % resp[1:], end="\r", flush=True)
            else:
                progress_indicator = ''.join(random.choices("!@#$%^&*()_+", k=16))
                print(progress_indicator, end="\r", flush=True)



    except UcError as e:
        print("ERROR: %s" % e)


if __name__ == '__main__':
    test_thumb()
