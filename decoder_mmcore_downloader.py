# Author:		          PureReactions
# Description:            Decodes URI in MMCore-Banechant Downloader variant
# External Dependencies   capstone, pefile
# Reference(s):           https://blogs.forcepoint.com/security-labs/mm-core-memory-backdoor-returns-bigboss-and-sillygoose
#                           https://www.contextis.com/blog/attackers-exhibit-strangelove-for-middle-eastern-targets

import pefile, sys, argparse, binascii 
from capstone import *
from capstone.x86 import *


prmtrs = argparse.ArgumentParser(description="This Python script decodes the URL Path from the MMCore-Banechant downloader component")
prmtrs.add_argument("--file", help="File")
prmtr = prmtrs.parse_args()

def dcd_url(tbl, lst):
    nw_lst = []
    url = ""
    for i in lst:
        if i in tbl:
            nw_lst.append(i)
    for i in nw_lst:
        url += tbl[i]
    return url

def prs_fnc(exc_cd):
    fncs = exc_cd
    dsmblr = Cs(CS_ARCH_X86, CS_MODE_32)
    dsmblr.detail = True
    cd_lngth = len(fncs)
    ot = []
    for i in dsmblr.disasm(fncs, cd_lngth):
        if i.id == (X86_INS_MOV):
            for n in i.operands:
                if n.type == X86_OP_IMM:
                    ky = format(n.imm, '04x')
                    if len(ky) == 4:
                        ot.append(ky)
    return ot

def prs_tbl(tbl):
    nw_tbl = [ tbl[i:i+4] for i in range(0, len(tbl), 4)]
    asc_tbl = {}
    for i in nw_tbl:
        asc_tbl.update({binascii.hexlify(i[-3]+i[-4]) : i[-2]})
    return asc_tbl

def extrct_txt_sctn():
    for sctn in pefile.PE(prmtr.file).sections:
        if sctn.Name.rstrip("\x00") == ".text":
            return sctn.get_data()

def extrct_dt_sctn():
    for sctn in pefile.PE(prmtr.file).sections:
        if sctn.Name.rstrip("\x00") == ".data":
            return sctn.get_data()[-0x1B0:]

def rn():
    tbl = prs_tbl(extrct_dt_sctn())
    ky_lst = prs_fnc(extrct_txt_sctn())
    c2 = dcd_url(tbl, ky_lst)
    print ("URL Payload:\n%s" %c2)
    

if "__name__" == "__main__":
    rn()
else:
    rn()


