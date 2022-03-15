module Ebpf.Asm where

import Data.Int (Int64)

data BinAlu = Add | Sub | Mul | Div | Or | And | Lsh | Rsh | Mod | Xor
  | Mov | Arsh
  deriving (Eq, Show, Ord, Enum)

data UnAlu = Neg | Le | Be
  deriving (Eq, Show, Ord, Enum)

data BSize = B8 | B16 | B32 | B64
  deriving (Eq, Show, Ord, Enum)

data Jcmp = Jeq | Jgt | Jge | Jlt | Jle | Jset | Jne | Jsgt | Jsge | Jslt | Jsle
  deriving (Eq, Show, Ord, Enum)

--data Reg = R0 | R1 | R2 | R3 | R4 | R5 | R6 | R7 | R8 | R9 | R10
newtype Reg = Reg Int  deriving (Eq, Show, Ord)
type Imm = Int64
type RegImm = Either Reg Imm
type Offset = Int64

-- TODO support atomic operations
-- TODO support absolute and indirect loads
-- TODO support tail calls

data Instruction =
    Binary BSize BinAlu Reg RegImm
  | Unary BSize UnAlu Reg
  | Store BSize Reg (Maybe Offset) RegImm
  | Load BSize Reg Reg (Maybe Offset)
  | LoadImm Reg Imm
  | LoadMapFd Reg Imm
  | JCond Jcmp Reg RegImm Offset
  | Jmp Offset
  | Call Imm
  | Exit
  deriving (Eq, Show, Ord)

type Program = [Instruction]

-- TODO add wellformed-ness check
