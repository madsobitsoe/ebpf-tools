{-# LANGUAGE NumericUnderscores #-}
module Ebpf.Elf where

import Ebpf.Asm
import Data.Word
import Data.Bits
import Ebpf.Encode

import qualified Data.ByteString as B

w64 :: Integral n => n -> Word64
w64 = fromIntegral

pack16 :: Word16 -> B.ByteString
pack16 w = B.pack [w8 $ w .&. 0xff,
                   w8 $ w `rotateR` 8]

pack32 :: Word32 -> B.ByteString
pack32 w = B.pack [w8 $ w .&. 0xff ,
                   w8 $ w `rotateR` 8,
                   w8 $ w `rotateR` 16,
                   w8 $ w `rotateR` 24
                   ]

pack64 :: Word64 -> B.ByteString
pack64 w = B.pack [w8 $ w .&. 0xff ,
                   w8 $ w `rotateR` 8,
                   w8 $ w `rotateR` 16,
                   w8 $ w `rotateR` 24,
                   w8 $ w `rotateR` 32,
                   w8 $ w `rotateR` 40,
                   w8 $ w `rotateR` 48,
                   w8 $ w `rotateR` 56
                   ]

w64Tow8List :: Word64 -> [Word8]
w64Tow8List w = [w8 $ w .&. 0xff ,
                   w8 $ w `rotateR` 8,
                   w8 $ w `rotateR` 16,
                   w8 $ w `rotateR` 24,
                   w8 $ w `rotateR` 32,
                   w8 $ w `rotateR` 40,
                   w8 $ w `rotateR` 48,
                   w8 $ w `rotateR` 56
                   ]

addElfHeader :: B.ByteString  -> B.ByteString
addElfHeader program =
  let programSize = B.length program
      sizeAsBytes = pack64 $ w64 programSize
      headerPart1 = B.pack [
        0x7f, 0x45, 0x4c, 0x46, -- ELF magic
        0x02, 0x01, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, -- elfType, 1 means "REL (Relocatable file)"
        0xf7, 0x00, -- elfMachine, 0xf7 is Linux BPF
        0x01, 0x00, 0x00, 0x00, -- elfVersion
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -- elfEntry
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -- elfProgram header offset
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -- section header offset
        0x00, 0x00, 0x00, 0x00, -- elfFlags
        0x40, 0x00, -- elf Header Size
        0x00, 0x00, -- elf program header size
        0x00, 0x00, -- elf program header number
        0x00, 0x00, -- elf section header size
        0x00, 0x00, -- elf section header number
        0x00, 0x00, -- elf section header strndx
        0x01, 0x00, 0x00, 0x00, -- elf PType
        0x05, 0x00, 0x00, 0x00, -- elf PFlags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, -- elf p offset
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, -- elf PVAddr
        0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00] -- elf PAddr
      headerPart2 = B.pack [0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00] -- elf PAlign
  in
    headerPart1 `B.append` sizeAsBytes `B.append` sizeAsBytes `B.append` headerPart2 `B.append` program
