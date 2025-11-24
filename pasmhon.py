#!/usr/bin/env python3

import sys, re, os, stat, subprocess
from dataclasses import dataclass

# =========================
# ELF backend (same idea as before)
# =========================

BASE   = 0x400000
CODEVA = BASE + 0x80
DATAVA = BASE + 0x100

def build_print(msg: bytes) -> bytes:
    code = []
    # write(1, msg, len)
    code += [0x48,0xc7,0xc0,1,0,0,0]                     # mov rax,1
    code += [0x48,0xc7,0xc7,1,0,0,0]                     # mov rdi,1
    code += [0x48,0xbe] + list(DATAVA.to_bytes(8,'little'))  # mov rsi,msg
    code += [0x48,0xc7,0xc2] + list(len(msg).to_bytes(4,'little'))  # mov rdx,len
    code += [0x0f,0x05]                                  # syscall
    # exit(0)
    code += [0x48,0xc7,0xc0,60,0,0,0]                    # mov rax,60
    code += [0x48,0x31,0xff]                             # xor rdi,rdi
    code += [0x0f,0x05]                                  # syscall
    return bytes(code)

def elf64(code: bytes, data: bytes) -> bytes:
    # ELF header
    eh = bytearray()
    eh += b"\x7fELF"          # magic
    eh += b"\x02"             # 64 bit
    eh += b"\x01"             # little endian
    eh += b"\x01"             # version
    eh += b"\x00"*9           # padding
    eh += (2).to_bytes(2,'little')      # type EXEC
    eh += (0x3e).to_bytes(2,'little')   # machine x86_64
    eh += (1).to_bytes(4,'little')      # version
    eh += CODEVA.to_bytes(8,'little')   # entry point
    eh += (64).to_bytes(8,'little')     # program header offset
    eh += (0).to_bytes(8,'little')      # section header offset
    eh += (0).to_bytes(4,'little')      # flags
    eh += (64).to_bytes(2,'little')     # ELF header size
    eh += (56).to_bytes(2,'little')     # PH entry size
    eh += (1).to_bytes(2,'little')      # PH count
    eh += (0).to_bytes(2,'little')      # SH entry size
    eh += (0).to_bytes(2,'little')      # SH count
    eh += (0).to_bytes(2,'little')      # SH string index

    # Program header
    ph = bytearray()
    ph += (1).to_bytes(4,'little')           # PT_LOAD
    ph += (5).to_bytes(4,'little')           # PF_R | PF_X
    ph += (0).to_bytes(8,'little')           # file offset
    ph += BASE.to_bytes(8,'little')          # vaddr
    ph += BASE.to_bytes(8,'little')          # paddr
    file_size = 0x100 + len(data)
    ph += file_size.to_bytes(8,'little')     # file size
    ph += file_size.to_bytes(8,'little')     # mem size
    ph += (0x1000).to_bytes(8,'little')      # alignment

    # pad headers to 0x80 where code begins
    while len(eh) + len(ph) < 0x80:
        ph += b"\x00"

    blob = bytearray()
    blob += eh
    blob += ph
    blob += code

    # pad to 0x100 where data begins
    while len(blob) < 0x100:
        blob += b"\x00"

    blob += data
    return bytes(blob)

# =========================
# Lexer
# =========================

@dataclass
class Token:
    type: str
    value: object

KEYWORDS = {
    "print": "PRINT",
    "if": "IF",
    "def": "DEF",
    "return": "RETURN",
}

def tokenize(line: str):
    tokens = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c in " \t":
            i += 1
            continue
        if c.isdigit():
            start = i
            while i < n and line[i].isdigit():
                i += 1
            tokens.append(Token("INT", int(line[start:i])))
            continue
        if c.isalpha() or c == "_":
            start = i
            while i < n and (line[i].isalnum() or line[i] == "_"):
                i += 1
            ident = line[start:i]
            ttype = KEYWORDS.get(ident, "IDENT")
            tokens.append(Token(ttype, ident))
            continue
        if c == '"':
            i += 1
            start = i
            buf = []
            while i < n and line[i] != '"':
                # bare minimum, no fancy escapes
                buf.append(line[i])
                i += 1
            if i >= n or line[i] != '"':
                raise SyntaxError("unterminated string")
            i += 1
            tokens.append(Token("STRING", "".join(buf)))
            continue
        # multi char operators
        if c in "=!<>" and i + 1 < n and line[i+1] == "=":
            two = c + "="
            ttype = {
                "==": "EQEQ",
                "!=": "NE",
                "<=": "LE",
                ">=": "GE",
            }[two]
            tokens.append(Token(ttype, two))
            i += 2
            continue
        # single char tokens
        single = {
            "+": "PLUS",
            "-": "MINUS",
            "*": "STAR",
            "/": "SLASH",
            "(": "LPAREN",
            ")": "RPAREN",
            ":": "COLON",
            ",": "COMMA",
            "<": "LT",
            ">": "GT",
            "=": "EQ",
        }
        if c in single:
            tokens.append(Token(single[c], c))
            i += 1
            continue
        raise SyntaxError(f"unexpected character {c!r}")
    tokens.append(Token("EOF", None))
    return tokens

# =========================
# AST nodes
# =========================

@dataclass
class Program:
    stmts: list

# statements
@dataclass
class Assign:
    name: str
    expr: object

@dataclass
class Print:
    expr: object

@dataclass
class If:
    cond: object
    body: object

@dataclass
class FuncDef:
    name: str
    param: str
    body: object

@dataclass
class Return:
    expr: object

@dataclass
class ExprStmt:
    expr: object

# expressions
@dataclass
class IntLit:
    value: int

@dataclass
class StringLit:
    value: str

@dataclass
class Var:
    name: str

@dataclass
class BinOp:
    op: str
    left: object
    right: object

@dataclass
class Call:
    name: str
    arg: object | None

# =========================
# Parser (recursive descent)
# =========================

class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0

    @property
    def cur(self):
        return self.tokens[self.i]

    def eat(self, ttype):
        if self.cur.type != ttype:
            raise SyntaxError(f"expected {ttype}, got {self.cur.type}")
        self.i += 1

    def parse_program(self, src: str) -> Program:
        lines = [ln.strip() for ln in src.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        stmts = []
        for ln in lines:
            self.tokens = tokenize(ln)
            self.i = 0
            stmts.append(self.parse_stmt())
            if self.cur.type != "EOF":
                raise SyntaxError("extra tokens at end of line")
        return Program(stmts)

    def parse_stmt(self):
        if self.cur.type == "DEF":
            return self.parse_funcdef()
        if self.cur.type == "IF":
            return self.parse_if()
        if self.cur.type == "RETURN":
            return self.parse_return()
        return self.parse_simple_stmt()

    def parse_simple_stmt(self):
        if self.cur.type == "PRINT":
            return self.parse_print()
        if self.cur.type == "IDENT" and self.tokens[self.i+1].type == "EQ":
            return self.parse_assign()
        expr = self.parse_expr()
        return ExprStmt(expr)

    def parse_print(self):
        self.eat("PRINT")
        self.eat("LPAREN")
        expr = self.parse_expr()
        self.eat("RPAREN")
        return Print(expr)

    def parse_assign(self):
        name = self.cur.value
        self.eat("IDENT")
        self.eat("EQ")
        expr = self.parse_expr()
        return Assign(name, expr)

    def parse_if(self):
        self.eat("IF")
        cond = self.parse_expr()
        self.eat("COLON")
        body = self.parse_simple_stmt()
        return If(cond, body)

    def parse_funcdef(self):
        self.eat("DEF")
        if self.cur.type != "IDENT":
            raise SyntaxError("expected function name")
        name = self.cur.value
        self.eat("IDENT")
        self.eat("LPAREN")
        if self.cur.type != "IDENT":
            raise SyntaxError("expected parameter name")
        param = self.cur.value
        self.eat("IDENT")
        self.eat("RPAREN")
        self.eat("COLON")
        body = self.parse_simple_stmt()
        return FuncDef(name, param, body)

    def parse_return(self):
        self.eat("RETURN")
        expr = self.parse_expr()
        return Return(expr)

    # expression grammar
    def parse_expr(self):
        return self.parse_equality()

    def parse_equality(self):
        node = self.parse_comparison()
        while self.cur.type in ("EQEQ", "NE"):
            op = self.cur.value
            self.eat(self.cur.type)
            right = self.parse_comparison()
            node = BinOp(op, node, right)
        return node

    def parse_comparison(self):
        node = self.parse_term()
        while self.cur.type in ("LT", "GT", "LE", "GE"):
            op_map = {
                "LT": "<",
                "GT": ">",
                "LE": "<=",
                "GE": ">=",
            }
            op = op_map[self.cur.type]
            self.eat(self.cur.type)
            right = self.parse_term()
            node = BinOp(op, node, right)
        return node

    def parse_term(self):
        node = self.parse_factor()
        while self.cur.type in ("PLUS", "MINUS"):
            op = "+" if self.cur.type == "PLUS" else "-"
            self.eat(self.cur.type)
            right = self.parse_factor()
            node = BinOp(op, node, right)
        return node

    def parse_factor(self):
        node = self.parse_unary()
        while self.cur.type in ("STAR", "SLASH"):
            op = "*" if self.cur.type == "STAR" else "/"
            self.eat(self.cur.type)
            right = self.parse_unary()
            node = BinOp(op, node, right)
        return node

    def parse_unary(self):
        if self.cur.type == "PLUS":
            self.eat("PLUS")
            return self.parse_unary()
        if self.cur.type == "MINUS":
            self.eat("MINUS")
            expr = self.parse_unary()
            return BinOp("*", IntLit(-1), expr)
        return self.parse_primary()

    def parse_primary(self):
        tok = self.cur
        if tok.type == "INT":
            self.eat("INT")
            return IntLit(tok.value)
        if tok.type == "STRING":
            self.eat("STRING")
            return StringLit(tok.value)
        if tok.type == "IDENT":
            name = tok.value
            self.eat("IDENT")
            if self.cur.type == "LPAREN":
                # simple function call, zero or one argument
                self.eat("LPAREN")
                if self.cur.type == "RPAREN":
                    self.eat("RPAREN")
                    return Call(name, None)
                arg = self.parse_expr()
                self.eat("RPAREN")
                return Call(name, arg)
            return Var(name)
        if tok.type == "LPAREN":
            self.eat("LPAREN")
            expr = self.parse_expr()
            self.eat("RPAREN")
            return expr
        raise SyntaxError(f"unexpected token {tok.type}")

# =========================
# Interpreter over AST
# =========================

class ReturnException(Exception):
    def __init__(self, value):
        self.value = value

class Env:
    def __init__(self, parent=None):
        self.vars = {}
        self.funcs = {}
        self.parent = parent

    def get_var(self, name):
        if name in self.vars:
            return self.vars[name]
        if self.parent:
            return self.parent.get_var(name)
        raise NameError(f"undefined variable {name}")

    def set_var(self, name, value):
        self.vars[name] = value

    def get_func(self, name):
        if name in self.funcs:
            return self.funcs[name]
        if self.parent:
            return self.parent.get_func(name)
        raise NameError(f"undefined function {name}")

    def set_func(self, name, fn):
        self.funcs[name] = fn

@dataclass
class FunctionObject:
    name: str
    param: str
    body: object
    env: Env

def eval_program(prog: Program) -> str:
    env = Env()
    out = []
    for stmt in prog.stmts:
        eval_stmt(stmt, env, out)
    return "".join(out)

def eval_stmt(stmt, env: Env, out: list):
    if isinstance(stmt, Assign):
        val = eval_expr(stmt.expr, env)
        env.set_var(stmt.name, val)
    elif isinstance(stmt, Print):
        val = eval_expr(stmt.expr, env)
        out.append(str(val) + "\n")
    elif isinstance(stmt, If):
        cond = eval_expr(stmt.cond, env)
        if bool(cond):
            eval_stmt(stmt.body, env, out)
    elif isinstance(stmt, FuncDef):
        fn = FunctionObject(stmt.name, stmt.param, stmt.body, env)
        env.set_func(stmt.name, fn)
    elif isinstance(stmt, Return):
        val = eval_expr(stmt.expr, env)
        raise ReturnException(val)
    elif isinstance(stmt, ExprStmt):
        eval_expr(stmt.expr, env)
    else:
        raise RuntimeError("unknown statement")

def eval_expr(expr, env: Env):
    if isinstance(expr, IntLit):
        return expr.value
    if isinstance(expr, StringLit):
        return expr.value
    if isinstance(expr, Var):
        return env.get_var(expr.name)
    if isinstance(expr, BinOp):
        left = eval_expr(expr.left, env)
        right = eval_expr(expr.right, env)
        op = expr.op
        if op in ("+", "-", "*", "/"):
            if op == "+":
                # allow int plus int, or string concat
                if isinstance(left, str) or isinstance(right, str):
                    return str(left) + str(right)
                return int(left) + int(right)
            if op == "-":
                return int(left) - int(right)
            if op == "*":
                return int(left) * int(right)
            if op == "/":
                return int(left) // int(right)
        if op in ("<", ">", "<=", ">=", "==", "!="):
            if op == "<":
                return left < right
            if op == ">":
                return left > right
            if op == "<=":
                return left <= right
            if op == ">=":
                return left >= right
            if op == "==":
                return left == right
            if op == "!=":
                return left != right
        raise RuntimeError(f"unsupported operator {op}")
    if isinstance(expr, Call):
        fn = env.get_func(expr.name)
        local = Env(parent=fn.env)
        if fn.param is not None:
            if expr.arg is not None:
                arg_val = eval_expr(expr.arg, env)
                local.set_var(fn.param, arg_val)
            else:
                local.set_var(fn.param, None)
        try:
            eval_stmt(fn.body, local, out=[])
            return None
        except ReturnException as r:
            return r.value
    raise RuntimeError("unknown expression")

# =========================
# pasmhon main
# =========================

def main():
    if len(sys.argv) != 2:
        print("usage: pasmhon main.pa")
        sys.exit(1)

    src = open(sys.argv[1]).read()

    # front end: parse to AST
    parser = Parser([])
    prog = parser.parse_program(src)

    # run at compile time to compute full output string
    out_text = eval_program(prog)
    msg = out_text.encode("utf8")

    # backend: emit native code that just writes this output
    code = build_print(msg)
    binfile = elf64(code, msg)

    os.makedirs("build", exist_ok=True)
    out_path = "build/main"
    with open(out_path, "wb") as f:
        f.write(binfile)
    os.chmod(out_path, os.stat(out_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    # run the compiled binary so pasmhon behaves like python3
    proc = subprocess.run([out_path], text=True, capture_output=True)
    if proc.stdout:
        print(proc.stdout, end="")
    if proc.stderr:
        print(proc.stderr, end="", file=sys.stderr)
    sys.exit(proc.returncode)

if __name__ == "__main__":
    main()
