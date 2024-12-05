#!/usr/bin/python

f = open('code.asm')

lines = f.readlines()

keywords = {"MOVRR" : 1,
            "MOVRV" : 2,
            "MOVRM" : 3, 
            "MOVMR" : 4,
            "ADDRR" : 0x21,
            "ADDRV" : 0x22,
            "XORRR" : 0x11,
            "XORRV" : 0x12,
            "CMPRR" : 0x60,
            "JUMP" : 0x50,
            "JE" : 0x51,
            "JL" : 0x52,
            "IOOUT" : 0x90,
            "IOIN" : 0x91}

print(lines)
