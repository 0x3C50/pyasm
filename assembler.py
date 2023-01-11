import dataclasses
import math
import opcode
from types import CodeType
from typing import Any


class _insn:
    def __init__(self, opcode: int, arg: int):
        self.opc = opcode
        self.arg = arg

    def to_bc_seq(self):
        bl = self.arg.bit_length()
        if bl > 4 * 8:
            raise ValueError(f"Arg {self.arg} is too big to pack into 4 bytes")
        arg_bytes = self.arg.to_bytes(math.ceil(bl / 8), "big", signed=False)
        if len(arg_bytes) == 0:
            arg_bytes = b"\x00"
        constructed = []
        if len(arg_bytes) > 1:
            for x in arg_bytes[:-1]:
                constructed += [0x90, x]  # EXTENDED_ARG x
        constructed += [self.opc, arg_bytes[len(arg_bytes) - 1]]
        cache = opcode._inline_cache_entries[self.opc]
        constructed += [0x00] * cache * 2
        return bytes(constructed)


class Label(_insn):
    """
    Denotes a label
    """

    def __init__(self):
        super().__init__(-1, -1)

    def to_bc_seq(self):
        return b""


@dataclasses.dataclass
class ExcTableE:
    from_lbl: Label
    to_lbl: Label
    handler_lbl: Label
    depth: int
    lasti: bool

    def to_bc_seq(self, assembluh):
        st = assembluh.label_codepos(self.from_lbl)
        en = assembluh.label_codepos(self.to_lbl)
        handler = assembluh.label_codepos(self.handler_lbl)
        return (
            _encode_varint(st // 2)
            + _encode_varint((en - st) // 2)
            + _encode_varint(handler // 2)
            + _encode_varint(self.depth << 1 | int(self.lasti))
        )


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

    # class TryCatchBuilder:
    #     """
    #     Context manager for a try block
    #     """
    #
    #     def __init__(self, assembler, depth: int, lasti: bool):
    #         self.assembler = assembler
    #         self.start = -1
    #         self.end = -1
    #         self.target = -1
    #         self.depth = depth
    #         self.li = lasti
    #
    #     def __enter__(self):
    #         self.start = self.assembler.current_bytecode_index()
    #
    #     def __exit__(self, exc_type, exc_val, exc_tb):
    #         if self.start == -1:
    #             raise ValueError("__exit__ called before __enter__ (?)")
    #         self.end = self.assembler.current_bytecode_index()
    #         self.target = (
    #             self.end
    #         )  # weird but it does work, assume handler is directly after
    #         self.assembler.add_exception_table_span(
    #             self.start, self.end, self.target, self.depth, self.li
    #         )

    def __init__(self, arg_names: list[str] = None):
        """
        Creates a new assembler
        :param arg_names: The argument names, if this assembler describes a method. None otherwise (and by default).
        """
        if arg_names is None:
            arg_names = list()
        self.insns = []
        self.consts = []
        self.names = []
        self.varnames = []
        self.exc_table_entries = []
        self.argnames = arg_names
        for n in arg_names:
            self.locals_create_or_get(n)

    def current_bytecode_index(self):
        """
        Returns the length of the currently built bytecode sequence (aka the index of the next instruction)
        :return: the length of the currently built bytecode sequence
        """
        return len(self._build_co_str())

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
        bc = b"".join([x.to_bc_seq() for x in self.insns[:idx]])
        return len(bc)

    def label(self, lbl: Label = None) -> Label:
        """
        Adds or creates a label
        :param lbl: The label to add. May be None
        :return: The added label, either new or lbl
        """
        if lbl is None:
            lbl = Label()
        if lbl in self.insns:
            raise ValueError("Label already registered")
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
        insn = _insn(opcode, arg)
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
            ExcTableE(from_lbl, to_lbl, target_lbl, depth, is_lasti)
        )

    def _build_co_str(self) -> bytes:
        b = b""
        for x in self.insns:
            b += x.to_bc_seq()
        return b

    def _build_exc_table(self) -> bytes:
        b = b""
        for x in self.exc_table_entries:
            b += x.to_bc_seq(self)
        return b

    def pack_code_object(self) -> CodeType:
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
            self._build_co_str(),
            tuple(self.consts),
            tuple(self.names),
            tuple(self.varnames),
            "<asm>",
            "",
            "",
            0,
            b"",
            self._build_exc_table(),
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
