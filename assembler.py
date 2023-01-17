import dataclasses
import math
import opcode
from types import CodeType
from typing import Any


@dataclasses.dataclass
class Insn:
    """
    Denotes an instruction
    """

    opc: int
    arg: int


class Label(Insn):
    """
    Denotes a label
    """

    def __init__(self):
        super().__init__(-1, -1)

    def __eq__(self, other):
        return id(other) == id(self)  # strict eq


@dataclasses.dataclass
class ExcTableEntry:
    from_lbl: Label
    to_lbl: Label
    handler_lbl: Label
    depth: int
    lasti: bool


class VersionCodec:
    def encode_trycatch(self, exc_entry: ExcTableEntry, assembler) -> bytes:
        raise NotImplementedError()

    def encode_insn(self, insn: Insn, assembler) -> bytes:
        raise NotImplementedError()


class VerCodec311(VersionCodec):
    def encode_trycatch(self, exc_entry: ExcTableEntry, assembler) -> bytes:
        st = assembler.label_codepos(exc_entry.from_lbl)
        en = assembler.label_codepos(exc_entry.to_lbl)
        handler = assembler.label_codepos(exc_entry.handler_lbl)
        return (
            _encode_varint(st // 2)
            + _encode_varint((en - st) // 2)
            + _encode_varint(handler // 2)
            + _encode_varint(exc_entry.depth << 1 | int(exc_entry.lasti))
        )

    def encode_insn(self, insn: Insn, assembler) -> bytes:
        if type(insn) == Label:
            return b""  # special case: no content
        bl = insn.arg.bit_length()
        if bl > 4 * 8:
            raise ValueError(f"Arg {insn.arg} is too big to pack into 4 bytes")
        arg_bytes = insn.arg.to_bytes(math.ceil(bl / 8), "big", signed=False)
        if len(arg_bytes) == 0:
            arg_bytes = b"\x00"
        constructed = []
        if len(arg_bytes) > 1:
            for x in arg_bytes[:-1]:
                constructed += [0x90, x]  # EXTENDED_ARG x
        constructed += [insn.opc, arg_bytes[len(arg_bytes) - 1]]
        cache = opcode._inline_cache_entries[insn.opc]
        constructed += [0x00] * cache * 2
        return bytes(constructed)


def _encode_varint(value) -> bytes:
    a = value
    v = 0
    while a > 0:  # reverse bytes of a
        v |= a & 63
        v = v << 6
        a = a >> 6
    b = []
    while v > 0:
        val = v & 0b11_11_11  # 6 bits at once
        v = v >> 6  # shift 6 bits right
        if v > 0:
            val = val | 0b1_00_00_00  # add cont bit, we have a next byte to encode
        b.append(val)  # add byte to the result
    if len(b) == 0:  # nothing encoded
        b = [0x00]
    return bytes(b)


class Assembler:
    """
    An assembler for python bytecode
    """

    def __init__(self, arg_names: list[str] = None, codec: VersionCodec = None):
        """
        Creates a new assembler
        :param arg_names: The argument names, if this assembler describes a method. None otherwise (and by default).
        :param codec: The version codec
        """
        if arg_names is None:
            arg_names = list()
        self.insns: list[Insn] = []
        self.consts: list[Any] = []
        self.names: list[str] = []
        self.varnames: list[str] = []
        self.exc_table_entries: list[ExcTableEntry] = []
        self.argnames: list[str] = arg_names
        self.codec: VersionCodec = codec if codec is not None else VerCodec311()
        for n in arg_names:
            self.locals_create_or_get(n)

    def current_bytecode_index(self):
        """
        Returns the length of the currently built bytecode sequence (aka the index of the next instruction)
        :return: the length of the currently built bytecode sequence
        """
        return len(self.build_bytecode())

    def insn(self, name: str, arg: int = 0):
        """
        Adds an insn by name. See `opcode.py` for all opcodes.
        :param name: The name of the insn to add
        :param arg: The argument. 0 by default
        :raises ValueError: if the name of the insn couldn't be resolved
        :return: Nothing
        """
        name = name.upper()
        if name not in opcode.opmap:
            raise ValueError("Unknown insn " + name)
        opm = opcode.opmap[name]
        self.add_insn(opm, arg)

    def label_codepos(self, lbl: Label):
        if lbl not in self.insns:
            raise ValueError(
                "Label wasn't found. Register label first using assembler.label()"
            )
        idx = self.insns.index(lbl)
        bc = b"".join([self.codec.encode_insn(x, self) for x in self.insns[:idx]])
        return len(bc)

    def label(self, lbl: Label = None) -> Label:
        """
        Adds or creates a label
        :param lbl: The label to add. May be None
        :return: The added label, either new or lbl
        """
        if lbl is None:
            lbl = Label()
        self.insns.append(lbl)
        return lbl

    def add_insn(self, opcode: int, arg: int = 0):
        """
        Adds an insn by opcode. Use insn(str, int) for an easier-to-use implementation.
        :param opcode: The opcode (0-255)
        :param arg: The argument. 0 by default
        :return: Nothing
        :raises ValueError: If either the opcode is not within 0-255, or arg is below 0
        """
        if opcode > 255 or opcode < 0:
            raise ValueError("Opcode not in range 0-255")
        if arg < 0:
            raise ValueError("arg out of bounds")
        insn = Insn(opcode, arg)
        self.insns.append(insn)

    def add_trycatch(
        self,
        from_lbl: Label,
        to_lbl: Label,
        target_lbl: Label,
        depth: int,
        is_lasti: bool,
    ):
        """
        Adds a try catch span
        :param from_lbl: The starting label of the try block
        :param to_lbl: The ending label of the try block
        :param target_lbl: The starting label of the catch block
        :param depth: Depth
        :param is_lasti: Unknown
        :return:
        """
        self.exc_table_entries.append(
            ExcTableEntry(from_lbl, to_lbl, target_lbl, depth, is_lasti)
        )

    def build_bytecode(self) -> bytes:
        """
        Builds a bytecode string representing this assembler
        :return: The bytecode string
        """
        b = b""
        for x in self.insns:
            b += self.codec.encode_insn(x, self)
        return b

    def build_exceptiontable(self) -> bytes:
        """
        Builds the exception table string
        :return: The exception table string
        """
        b = b""
        for x in self.exc_table_entries:
            b += self.codec.encode_trycatch(x, self)
        return b

    def build(self) -> CodeType:
        """
        Compiles this assembler into a code object
        :return: The constructed code object. Can be marshalled using marshal.dumps, or executed using eval() or exec()
        """
        return CodeType(
            len(self.argnames),
            0,
            0,
            len(self.varnames),
            30,
            0,
            self.build_bytecode(),
            tuple(self.consts),
            tuple(self.names),
            tuple(self.varnames),
            "<asm>",
            "",
            "",
            0,
            b"",
            self.build_exceptiontable(),
        )

    def consts_create_or_get(self, value: Any) -> int:
        """
        Creates or gets an entry from the constant pool
        :param value: The desired value
        :return: An existing or new index to the constant pool, where the specified value is
        """
        if value in self.consts:
            return self.consts.index(value)
        else:
            i = len(self.consts)
            self.consts.append(value)
            return i

    def names_create_or_get(self, value: str) -> int:
        """
        Creates or gets an entry from the name pool
        :param value: The desired value
        :return: An existing or new index to the name pool, where the specified value is
        """
        if value in self.names:
            return self.names.index(value)
        else:
            i = len(self.names)
            self.names.append(value)
            return i

    def locals_create_or_get(self, value: str) -> int:
        """
        Creates or gets an entry from the local pool
        :param value: The desired value
        :return: An existing or new index to the local pool, where the specified value is
        """
        if value in self.varnames:
            return self.varnames.index(value)
        else:
            i = len(self.varnames)
            self.varnames.append(value)
            return i
