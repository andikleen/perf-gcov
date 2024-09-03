from typing import BinaryIO, NamedTuple
from struct import pack

GCOV_TAG_AFDO_FILE_NAMES = 0xaa000000
GCOV_TAG_AFDO_FUNCTION = 0xac000000
GCOV_TAG_AFDO_MODULE_GROUPING = 0xae000000
GCOV_TAG_AFDO_WORKING_SET = 0xaf000000
GCOV_DATA_MAGIC = 0x67636461 # 'gcda'
GCOV_VERSION = 2
HIST_TYPE_INDIR_CALL_TOPN = 7

def w32(f: BinaryIO, v: int):
    f.write(pack("I", v))

def wstring(f: BinaryIO, s: str):
    s += "\0"
    w32(f, len(s))
    f.write(pack("%ds" % len(s), s.encode('utf-8')))

def wcounter(f: BinaryIO, v: int):
    w32(f, (v       ) & 0xffffffff)
    w32(f, (v >> 32 ) & 0xffffffff)

with open("file.gcov", "wb") as f:
    w32(f, GCOV_DATA_MAGIC)
    w32(f, GCOV_VERSION)
    w32(f, 0)

    # write string table
    w32(f, GCOV_TAG_AFDO_FILE_NAMES)
    w32(f, 0) # len (ignored)
    w32(f, 2) # num
    wstring(f, "foo")
    wstring(f, "bar")
        
    # write function profile
    w32(f, GCOV_TAG_AFDO_FUNCTION)
    w32(f, 0) # length (ignored)
    w32(f, 2) # num funcs
    
    wcounter(f, 99) # head count
    w32(f, 0) # name "foo"
    w32(f, 1) # 1 poscount
    w32(f, 0) # 0 callsites
    w32(f, 4 << 16) # offset
    w32(f, 0) # num targets
    wcounter(f, 64) # count

    wcounter(f, 12)
    w32(f, 1) # name "bar"
    w32(f, 1) # 1 poscount
    w32(f, 0) # 0 callsites
    w32(f, 5 << 16) # offset
    w32(f, 0) # num targets
    wcounter(f, 55) # count

    w32(f, GCOV_TAG_AFDO_MODULE_GROUPING)
    w32(f, 0)
    w32(f, 0)

    w32(f, GCOV_TAG_AFDO_WORKING_SET)
    w32(f, 0)
    w32(f, 0)
