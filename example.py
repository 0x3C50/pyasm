import dis

from assembler import Assembler


def functions():
    func1 = Assembler(["text"])
    func1.insn("RESUME", 0)

    func1.insn("PUSH_NULL")  # push NULL
    func1.insn("LOAD_NAME", func1.names_create_or_get("print"))  # load print
    func1.insn("LOAD_FAST", func1.locals_create_or_get("text"))  # load text arg
    func1.insn("PRECALL", 1)  # logical no-op, but apparently required
    func1.insn("CALL", 1)  # call with 1 arg
    func1.insn("POP_TOP")  # pop return value from print

    func1.insn("LOAD_CONST", func1.consts_create_or_get(None))  # load None
    func1.insn("RETURN_VALUE")  # return None

    asm = Assembler()
    asm.insn("RESUME", 0)

    asm.insn("LOAD_CONST", asm.consts_create_or_get(func1.pack_code_object()))  # load function's code object
    asm.insn("MAKE_FUNCTION")  # make function with code object
    asm.insn("STORE_NAME", asm.names_create_or_get("print_wrapper"))  # store as print_wrapper

    asm.insn("PUSH_NULL")  # push NULL
    asm.insn("LOAD_NAME", asm.names_create_or_get("print_wrapper"))  # load print_wrapper function
    asm.insn("LOAD_CONST", asm.consts_create_or_get("Hello world"))  # load "Hello world"
    asm.insn("PRECALL", 1)  # logical no-op, but apparently required
    asm.insn("CALL", 1)  # call with 1 arg
    asm.insn("POP_TOP")  # pop return value from print_wrapper

    asm.insn("LOAD_CONST", asm.consts_create_or_get(None))  # load None
    asm.insn("RETURN_VALUE")  # return None

    return asm.pack_code_object()


def hello_world():
    asm = Assembler()
    asm.insn("RESUME", 0)

    asm.insn("PUSH_NULL")  # push NULL
    asm.insn("LOAD_NAME", asm.names_create_or_get("print"))  # load print
    asm.insn("LOAD_CONST", asm.consts_create_or_get("Hello world"))  # load "Hello world"
    asm.insn("PRECALL", 1)  # logical no-op, but apparently required
    asm.insn("CALL", 1)  # call with 1 arg
    asm.insn("POP_TOP")  # pop return value from print

    asm.insn("LOAD_CONST", asm.consts_create_or_get(None))  # load None
    asm.insn("RETURN_VALUE")  # return None

    return asm.pack_code_object()


def try_catch():
    asm = Assembler()
    asm.insn("RESUME", 0)

    with asm.try_block(0, False):  # try block A
        asm.insn("PUSH_NULL")
        asm.insn("LOAD_NAME", asm.names_create_or_get("ValueError"))  # load ValueError method
        asm.insn("LOAD_CONST", asm.consts_create_or_get("Hello world"))  # push "Hello world" as argument
        asm.insn("PRECALL", 1)
        asm.insn("CALL", 1)  # init ValueError
        asm.insn("RAISE_VARARGS", 1)  # raise

    with asm.try_block(1, True):  # catch block to try block A, itself also try block B
        asm.insn("PUSH_EXC_INFO")  # push exception to top
        asm.insn("STORE_NAME", asm.names_create_or_get("e"))  # store exception in `e`

        asm.insn("PUSH_NULL")  # push NULL
        asm.insn("LOAD_NAME", asm.names_create_or_get("type"))  # load type method
        asm.insn("LOAD_NAME", asm.names_create_or_get("e"))  # call on `e`
        asm.insn("PRECALL", 1)
        asm.insn("CALL", 1)
        asm.insn("STORE_NAME", asm.names_create_or_get("e1"))  # store result in `e1`

        asm.insn("PUSH_NULL")
        asm.insn("LOAD_NAME", asm.names_create_or_get("print"))  # load print method
        asm.insn("LOAD_NAME", asm.names_create_or_get("e1"))  # load `e1`, type of `e`
        asm.insn("LOAD_NAME", asm.names_create_or_get("e"))  # load `e` itself
        asm.insn("PRECALL", 2)
        asm.insn("CALL", 2)  # call print(e1, e)
        asm.insn("POP_TOP")  # pop return value of print
        asm.insn("POP_EXCEPT")  # pop exception
        asm.insn("LOAD_CONST", asm.consts_create_or_get(None))
        asm.insn("RETURN_VALUE")  # return None

    # catch block to try block B, standard python practise.
    # if catch block A fails, reraise the exception
    asm.insn("COPY", 0)  # copy 0th stack item to top (the exception)
    asm.insn("POP_EXCEPT", 0)  # pop exception
    asm.insn("RERAISE", 1)  # raise exception

    return asm.pack_code_object()


def run_demo(fnc):
    print("-" * 5, "Demo", fnc.__name__, "-" * 5)
    code_obj = fnc()
    print("Disassembly:")
    dis.dis(code_obj)
    print("\nExec() result:")
    ret = exec(code_obj)
    print(f"( -> {ret})")


if __name__ == '__main__':
    run_demo(functions)
    run_demo(hello_world)
    run_demo(try_catch)
