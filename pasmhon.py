#!/usr/bin/env python3
import sys, re, os, stat, subprocess
from dataclasses import dataclass

# =========================
# ELF backend
# =========================

BASE   = 0x400000
CODEVA = BASE + 0x80
DATAVA = BASE + 0x100

def build_print(msg):
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

def elf64(code, data):
    # ELF header
    eh = bytearray()
    eh += b"\x7fELF"
    eh += b"\x02"
    eh += b"\x01"
    eh += b"\x01"
    eh += b"\x00"*9
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
    return blob

# =========================
# Global config for types / JIT / imports
# =========================

TYPE_MAP = {
    "int": int,
    "str": str,
    "list": list,
    "dict": dict,
}

JIT_THRESHOLD = 10
MODULE_CACHE = {}

# =========================
# Lexer
# =========================

@dataclass
class Token:
    type: str
    value: object

KEYWORDS = {
    "print":    "PRINT",
    "if":       "IF",
    "def":      "DEF",
    "return":   "RETURN",
    "while":    "WHILE",
    "for":      "FOR",
    "in":       "IN",
    "break":    "BREAK",
    "continue": "CONTINUE",
    "class":    "CLASS",
    "try":      "TRY",
    "except":   "EXCEPT",
    "raise":    "RAISE",
    "nonlocal": "NONLOCAL",
    "import":   "IMPORT",
}

def strip_block_comments(src):
    out = []
    i = 0
    n = len(src)
    while i < n:
        if i + 1 < n and src[i] == "/" and src[i+1] == "*":
            i += 2
            while i + 1 < n and not (src[i] == "*" and src[i+1] == "/"):
                i += 1
            if i + 1 >= n:
                break
            i += 2
            continue
        out.append(src[i])
        i += 1
    return "".join(out)

def lex_line(line):
    tokens = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c in " \t":
            i += 1
            continue
        if c == "#":
            break
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
            buf = []
            while i < n and line[i] != '"':
                buf.append(line[i])
                i += 1
            if i >= n or line[i] != '"':
                raise SyntaxError("unterminated string")
            i += 1
            tokens.append(Token("STRING", "".join(buf)))
            continue
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
            "[": "LBRACK",
            "]": "RBRACK",
            "{": "LBRACE",
            "}": "RBRACE",
            ".": "DOT",
        }
        if c in single:
            tokens.append(Token(single[c], c))
            i += 1
            continue
        raise SyntaxError(f"unexpected character {c!r}")
    return tokens

def lex(src):
    src = strip_block_comments(src)
    tokens = []
    indents = [0]
    for raw in src.splitlines():
        line = raw.rstrip("\r\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        stripped = line.lstrip(" ")
        indent = len(line) - len(stripped)
        if indent > indents[-1]:
            indents.append(indent)
            tokens.append(Token("INDENT", None))
        elif indent < indents[-1]:
            while indent < indents[-1]:
                indents.pop()
                tokens.append(Token("DEDENT", None))
            if indent != indents[-1]:
                raise SyntaxError("inconsistent indentation")
        tokens.extend(lex_line(stripped))
        tokens.append(Token("NEWLINE", None))
    while len(indents) > 1:
        indents.pop()
        tokens.append(Token("DEDENT", None))
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
class AttrAssign:
    obj: object
    name: str
    expr: object

@dataclass
class IndexAssign:
    seq: object
    index: object
    expr: object

@dataclass
class PrintStmt:
    expr: object

@dataclass
class IfStmt:
    cond: object
    body: list

@dataclass
class WhileStmt:
    cond: object
    body: list

@dataclass
class ForStmt:
    var: str
    iterable: object
    body: list

@dataclass
class ClassDef:
    name: str
    base_name: str | None
    body: list

@dataclass
class FuncDef:
    name: str
    params: list
    annotations: dict
    body: list

@dataclass
class ReturnStmt:
    expr: object

@dataclass
class BreakStmt:
    pass

@dataclass
class ContinueStmt:
    pass

@dataclass
class ExprStmt:
    expr: object

@dataclass
class TryStmt:
    body: list
    handler: list

@dataclass
class RaiseStmt:
    expr: object

@dataclass
class NonlocalStmt:
    names: list

@dataclass
class ImportStmt:
    module: str

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
class ListLit:
    elements: list

@dataclass
class DictLit:
    items: list   # list of (key_expr, value_expr)

@dataclass
class Index:
    seq: object
    index: object

@dataclass
class SliceIndex:
    seq: object
    start: object | None
    stop: object | None
    step: object | None

@dataclass
class Attr:
    obj: object
    name: str

@dataclass
class Call:
    name: str
    args: list

@dataclass
class MethodCall:
    obj: object
    name: str
    args: list

# =========================
# Parser
# =========================

class Parser:
    def __init__(self, tokens):
        self.tokens = tokens
        self.i = 0

    @property
    def cur(self):
        return self.tokens[self.i]

    def peek(self):
        return self.tokens[self.i+1]

    def eat(self, ttype):
        if self.cur.type != ttype:
            raise SyntaxError(f"expected {ttype}, got {self.cur.type}")
        self.i += 1

    def parse_program(self):
        stmts = []
        while self.cur.type != "EOF":
            if self.cur.type in ("NEWLINE", "DEDENT"):
                self.eat(self.cur.type)
                continue
            stmts.append(self.parse_stmt())
        return Program(stmts)

    def parse_stmt(self):
        if self.cur.type == "CLASS":
            return self.parse_classdef()
        if self.cur.type == "TRY":
            return self.parse_try()
        if self.cur.type == "IMPORT":
            return self.parse_import()
        if self.cur.type == "IF":
            return self.parse_if()
        if self.cur.type == "WHILE":
            return self.parse_while()
        if self.cur.type == "FOR":
            return self.parse_for()
        if self.cur.type == "DEF":
            return self.parse_funcdef()
        node = self.parse_simple_stmt()
        if self.cur.type == "NEWLINE":
            self.eat("NEWLINE")
        return node

    def parse_simple_stmt(self):
        if self.cur.type == "PRINT":
            return self.parse_print()
        if self.cur.type == "RETURN":
            return self.parse_return()
        if self.cur.type == "BREAK":
            self.eat("BREAK")
            return BreakStmt()
        if self.cur.type == "CONTINUE":
            self.eat("CONTINUE")
            return ContinueStmt()
        if self.cur.type == "NONLOCAL":
            return self.parse_nonlocal()
        if self.cur.type == "RAISE":
            return self.parse_raise()

        expr = self.parse_expr()
        if self.cur.type == "EQ" and isinstance(expr, (Var, Attr, Index)):
            self.eat("EQ")
            value = self.parse_expr()
            if isinstance(expr, Var):
                return Assign(expr.name, value)
            if isinstance(expr, Attr):
                return AttrAssign(expr.obj, expr.name, value)
            if isinstance(expr, Index):
                return IndexAssign(expr.seq, expr.index, value)
        return ExprStmt(expr)

    def parse_print(self):
        self.eat("PRINT")
        self.eat("LPAREN")
        expr = self.parse_expr()
        self.eat("RPAREN")
        return PrintStmt(expr)

    def parse_classdef(self):
        self.eat("CLASS")
        if self.cur.type != "IDENT":
            raise SyntaxError("expected class name")
        name = self.cur.value
        self.eat("IDENT")
        base_name = None
        if self.cur.type == "LPAREN":
            self.eat("LPAREN")
            if self.cur.type != "IDENT":
                raise SyntaxError("expected base class name")
            base_name = self.cur.value
            self.eat("IDENT")
            self.eat("RPAREN")
        self.eat("COLON")
        body = []
        if self.cur.type == "NEWLINE":
            self.eat("NEWLINE")
            self.eat("INDENT")
            while self.cur.type not in ("DEDENT", "EOF"):
                body.append(self.parse_stmt())
            self.eat("DEDENT")
        else:
            body.append(self.parse_simple_stmt())
            if self.cur.type == "NEWLINE":
                self.eat("NEWLINE")
        return ClassDef(name, base_name, body)

    def parse_try(self):
        self.eat("TRY")
        self.eat("COLON")
        body = []
        if self.cur.type == "NEWLINE":
            self.eat("NEWLINE")
            self.eat("INDENT")
            while self.cur.type not in ("DEDENT", "EOF"):
                body.append(self.parse_stmt())
            self.eat("DEDENT")
        else:
            body.append(self.parse_simple_stmt())
            if self.cur.type == "NEWLINE":
                self.eat("NEWLINE")
        if self.cur.type != "EXCEPT":
            raise SyntaxError("expected 'except' after try block")
        self.eat("EXCEPT")
        self.eat("COLON")
        handler = []
        if self.cur.type == "NEWLINE":
            self.eat("NEWLINE")
            self.eat("INDENT")
            while self.cur.type not in ("DEDENT", "EOF"):
                handler.append(self.parse_stmt())
            self.eat("DEDENT")
        else:
            handler.append(self.parse_simple_stmt())
            if self.cur.type == "NEWLINE":
                self.eat("NEWLINE")
        return TryStmt(body, handler)

    def parse_raise(self):
        self.eat("RAISE")
        expr = self.parse_expr()
        return RaiseStmt(expr)

    def parse_nonlocal(self):
        self.eat("NONLOCAL")
        names = []
        if self.cur.type != "IDENT":
            raise SyntaxError("expected name after nonlocal")
        names.append(self.cur.value)
        self.eat("IDENT")
        while self.cur.type == "COMMA":
            self.eat("COMMA")
            if self.cur.type != "IDENT":
                raise SyntaxError("expected name after nonlocal ','")
            names.append(self.cur.value)
            self.eat("IDENT")
        return NonlocalStmt(names)

    def parse_import(self):
        self.eat("IMPORT")
        if self.cur.type != "IDENT":
            raise SyntaxError("expected module name")
        name = self.cur.value
        self.eat("IDENT")
        return ImportStmt(name)

    def parse_if(self):
        self.eat("IF")
        cond_tokens = []
        while self.cur.type not in ("COLON", "EOF"):
            cond_tokens.append(self.cur)
            self.i += 1
        if self.cur.type != "COLON":
            raise SyntaxError("expected ':' after if condition")
        self.eat("COLON")
        cond_parser = Parser(cond_tokens + [Token("EOF", None)])
        cond = cond_parser.parse_expr()
        body = []
        if self.cur.type == "NEWLINE":
            self.eat("NEWLINE")
            self.eat("INDENT")
            while self.cur.type not in ("DEDENT", "EOF"):
                body.append(self.parse_stmt())
            self.eat("DEDENT")
        else:
            body.append(self.parse_simple_stmt())
            if self.cur.type == "NEWLINE":
                self.eat("NEWLINE")
        return IfStmt(cond, body)

    def parse_while(self):
        self.eat("WHILE")
        cond_tokens = []
        while self.cur.type not in ("COLON", "EOF"):
            cond_tokens.append(self.cur)
            self.i += 1
        if self.cur.type != "COLON":
            raise SyntaxError("expected ':' after while condition")
        self.eat("COLON")
        cond_parser = Parser(cond_tokens + [Token("EOF", None)])
        cond = cond_parser.parse_expr()
        body = []
        if self.cur.type == "NEWLINE":
            self.eat("NEWLINE")
            self.eat("INDENT")
            while self.cur.type not in ("DEDENT", "EOF"):
                body.append(self.parse_stmt())
            self.eat("DEDENT")
        else:
            body.append(self.parse_simple_stmt())
            if self.cur.type == "NEWLINE":
                self.eat("NEWLINE")
        return WhileStmt(cond, body)

    def parse_for(self):
        self.eat("FOR")
        if self.cur.type != "IDENT":
            raise SyntaxError("expected loop variable name")
        var = self.cur.value
        self.eat("IDENT")
        if self.cur.type != "IN":
            raise SyntaxError("expected 'in' in for loop")
        self.eat("IN")
        iter_tokens = []
        while self.cur.type not in ("COLON", "EOF"):
            iter_tokens.append(self.cur)
            self.i += 1
        if self.cur.type != "COLON":
            raise SyntaxError("expected ':' after for iterable")
        self.eat("COLON")
        iter_parser = Parser(iter_tokens + [Token("EOF", None)])
        iterable = iter_parser.parse_expr()
        body = []
        if self.cur.type == "NEWLINE":
            self.eat("NEWLINE")
            self.eat("INDENT")
            while self.cur.type not in ("DEDENT", "EOF"):
                body.append(self.parse_stmt())
            self.eat("DEDENT")
        else:
            body.append(self.parse_simple_stmt())
            if self.cur.type == "NEWLINE":
                self.eat("NEWLINE")
        return ForStmt(var, iterable, body)

    def parse_funcdef(self):
        self.eat("DEF")
        if self.cur.type != "IDENT":
            raise SyntaxError("expected function name")
        name = self.cur.value
        self.eat("IDENT")
        self.eat("LPAREN")
        params = []
        annotations = {}
        if self.cur.type == "IDENT":
            while True:
                pname = self.cur.value
                self.eat("IDENT")
                ptype = None
                if self.cur.type == "COLON":
                    self.eat("COLON")
                    if self.cur.type != "IDENT":
                        raise SyntaxError("expected type name")
                    ptype = self.cur.value
                    self.eat("IDENT")
                params.append(pname)
                if ptype is not None:
                    annotations[pname] = ptype
                if self.cur.type != "COMMA":
                    break
                self.eat("COMMA")
                if self.cur.type != "IDENT":
                    raise SyntaxError("expected parameter name")
        self.eat("RPAREN")
        self.eat("COLON")
        body = []
        if self.cur.type == "NEWLINE":
            self.eat("NEWLINE")
            self.eat("INDENT")
            while self.cur.type not in ("DEDENT", "EOF"):
                body.append(self.parse_stmt())
            self.eat("DEDENT")
        else:
            body.append(self.parse_simple_stmt())
            if self.cur.type == "NEWLINE":
                self.eat("NEWLINE")
        return FuncDef(name, params, annotations, body)

    def parse_return(self):
        self.eat("RETURN")
        expr = self.parse_expr()
        return ReturnStmt(expr)

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

    def parse_list_lit(self):
        self.eat("LBRACK")
        elements = []
        if self.cur.type != "RBRACK":
            elements.append(self.parse_expr())
            while self.cur.type == "COMMA":
                self.eat("COMMA")
                if self.cur.type == "RBRACK":
                    break
                elements.append(self.parse_expr())
        self.eat("RBRACK")
        return ListLit(elements)

    def parse_dict_lit(self):
        self.eat("LBRACE")
        items = []
        if self.cur.type != "RBRACE":
            key = self.parse_expr()
            self.eat("COLON")
            value = self.parse_expr()
            items.append((key, value))
            while self.cur.type == "COMMA":
                self.eat("COMMA")
                if self.cur.type == "RBRACE":
                    break
                key = self.parse_expr()
                self.eat("COLON")
                value = self.parse_expr()
                items.append((key, value))
        self.eat("RBRACE")
        return DictLit(items)

    def parse_atom(self):
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
                self.eat("LPAREN")
                args = []
                if self.cur.type != "RPAREN":
                    args.append(self.parse_expr())
                    while self.cur.type == "COMMA":
                        self.eat("COMMA")
                        if self.cur.type == "RPAREN":
                            break
                        args.append(self.parse_expr())
                self.eat("RPAREN")
                return Call(name, args)
            return Var(name)
        if tok.type == "LPAREN":
            self.eat("LPAREN")
            expr = self.parse_expr()
            self.eat("RPAREN")
            return expr
        if tok.type == "LBRACK":
            return self.parse_list_lit()
        if tok.type == "LBRACE":
            return self.parse_dict_lit()
        raise SyntaxError(f"unexpected token {tok.type}")

    def parse_primary(self):
        node = self.parse_atom()
        while True:
            if self.cur.type == "DOT":
                self.eat("DOT")
                if self.cur.type != "IDENT":
                    raise SyntaxError("expected name after '.'")
                name = self.cur.value
                self.eat("IDENT")
                if self.cur.type == "LPAREN":
                    self.eat("LPAREN")
                    args = []
                    if self.cur.type != "RPAREN":
                        args.append(self.parse_expr())
                        while self.cur.type == "COMMA":
                            self.eat("COMMA")
                            if self.cur.type == "RPAREN":
                                break
                            args.append(self.parse_expr())
                    self.eat("RPAREN")
                    node = MethodCall(node, name, args)
                else:
                    node = Attr(node, name)
            elif self.cur.type == "LBRACK":
                self.eat("LBRACK")
                if self.cur.type == "COLON":
                    start = None
                else:
                    start = self.parse_expr()
                if self.cur.type == "COLON":
                    self.eat("COLON")
                    if self.cur.type in ("RBRACK", "COLON"):
                        stop = None
                    else:
                        stop = self.parse_expr()
                    step = None
                    if self.cur.type == "COLON":
                        self.eat("COLON")
                        if self.cur.type == "RBRACK":
                            step = None
                        else:
                            step = self.parse_expr()
                    self.eat("RBRACK")
                    node = SliceIndex(node, start, stop, step)
                else:
                    self.eat("RBRACK")
                    node = Index(node, start)
            else:
                break
        return node

# =========================
# Bytecode VM
# =========================

@dataclass
class Instruction:
    op: str
    arg: object = None

def compile_program_to_bytecode(prog):
    instrs = []
    for stmt in prog.stmts:
        instrs.append(Instruction("EXEC_STMT", stmt))
    instrs.append(Instruction("HALT", None))
    return instrs

def run_bytecode(instrs, env):
    out = []
    ip = 0
    while ip < len(instrs):
        ins = instrs[ip]
        if ins.op == "EXEC_STMT":
            eval_stmt(ins.arg, env, out)
            ip += 1
        elif ins.op == "HALT":
            break
        else:
            raise RuntimeError(f"unknown opcode {ins.op}")
    return "".join(out)

# =========================
# Interpreter
# =========================

class ReturnException(Exception):
    def __init__(self, value):
        self.value = value

class BreakException(Exception):
    pass

class ContinueException(Exception):
    pass

class LangException(Exception):
    def __init__(self, value):
        self.value = value

class Env:
    def __init__(self, parent=None):
        self.vars = {}
        self.funcs = {}
        self.classes = {}
        self.parent = parent
        self.nonlocal_vars = set()

    def get_var(self, name):
        if name in self.vars:
            return self.vars[name]
        if self.parent:
            return self.parent.get_var(name)
        raise NameError(f"undefined variable {name}")

    def _set_nonlocal(self, name, value):
        if self.parent is None:
            raise NameError(f"no binding for nonlocal {name}")
        if name in self.parent.vars:
            self.parent.vars[name] = value
        else:
            self.parent._set_nonlocal(name, value)

    def set_var(self, name, value):
        if name in self.nonlocal_vars:
            self._set_nonlocal(name, value)
        else:
            self.vars[name] = value

    def declare_nonlocal(self, name):
        self.nonlocal_vars.add(name)

    def get_func(self, name):
        if name in self.funcs:
            return self.funcs[name]
        if self.parent:
            return self.parent.get_func(name)
        raise NameError(f"undefined function {name}")

    def set_func(self, name, fn):
        self.funcs[name] = fn

    def get_class(self, name):
        if name in self.classes:
            return self.classes[name]
        if self.parent:
            return self.parent.get_class(name)
        raise NameError(f"undefined class {name}")

    def set_class(self, name, cls):
        self.classes[name] = cls

@dataclass
class FunctionObject:
    name: str
    params: list
    body: list
    env: Env
    is_method: bool = False
    annotations: dict | None = None
    call_count: int = 0
    jit_impl: object | None = None

@dataclass
class ClassObject:
    name: str
    methods: dict
    attributes: dict
    base: "ClassObject | None" = None

@dataclass
class InstanceObject:
    cls: ClassObject
    fields: dict

@dataclass
class ModuleObject:
    name: str
    env: Env

def class_lookup_attr(cls, name):
    c = cls
    while c is not None:
        if name in c.attributes:
            return c.attributes[name]
        c = c.base
    return None

def class_lookup_method(cls, name):
    c = cls
    while c is not None:
        if name in c.methods:
            return c.methods[name]
        c = c.base
    return None

def eval_block(stmts, env, out):
    for s in stmts:
        eval_stmt(s, env, out)

def eval_program(prog):
    env = Env()
    bytecode = compile_program_to_bytecode(prog)
    return run_bytecode(bytecode, env)

def eval_stmt(stmt, env, out):
    if isinstance(stmt, Assign):
        val = eval_expr(stmt.expr, env)
        env.set_var(stmt.name, val)
    elif isinstance(stmt, AttrAssign):
        obj = eval_expr(stmt.obj, env)
        val = eval_expr(stmt.expr, env)
        if isinstance(obj, InstanceObject):
            obj.fields[stmt.name] = val
        else:
            raise RuntimeError("attribute assignment only supported on objects")
    elif isinstance(stmt, IndexAssign):
        seq = eval_expr(stmt.seq, env)
        idx = eval_expr(stmt.index, env)
        val = eval_expr(stmt.expr, env)
        try:
            seq[idx] = val
        except Exception as e:
            raise RuntimeError(f"index assignment error: {e}")
    elif isinstance(stmt, PrintStmt):
        val = eval_expr(stmt.expr, env)
        out.append(str(val) + "\n")
    elif isinstance(stmt, IfStmt):
        cond = eval_expr(stmt.cond, env)
        if bool(cond):
            eval_block(stmt.body, env, out)
    elif isinstance(stmt, WhileStmt):
        while bool(eval_expr(stmt.cond, env)):
            try:
                eval_block(stmt.body, env, out)
            except BreakException:
                break
            except ContinueException:
                continue
    elif isinstance(stmt, ForStmt):
        iterable_val = eval_expr(stmt.iterable, env)
        try:
            iterator = iter(iterable_val)
        except TypeError:
            raise RuntimeError("object not iterable in for loop")
        for value in iterator:
            env.set_var(stmt.var, value)
            try:
                eval_block(stmt.body, env, out)
            except BreakException:
                break
            except ContinueException:
                continue
    elif isinstance(stmt, ClassDef):
        class_env = Env(parent=env)
        tmp_out = []
        eval_block(stmt.body, class_env, tmp_out)
        methods = {}
        for name, fn in class_env.funcs.items():
            fn.is_method = True
            methods[name] = fn
        attrs = dict(class_env.vars)
        base_cls = None
        if stmt.base_name is not None:
            base_cls = env.get_class(stmt.base_name)
        cls_obj = ClassObject(stmt.name, methods, attrs, base_cls)
        env.set_class(stmt.name, cls_obj)
        env.set_var(stmt.name, cls_obj)
    elif isinstance(stmt, FuncDef):
        fn = FunctionObject(stmt.name, stmt.params, stmt.body, env,
                            is_method=False, annotations=stmt.annotations)
        env.set_var(stmt.name, fn)
        env.set_func(stmt.name, fn)
    elif isinstance(stmt, TryStmt):
        try:
            eval_block(stmt.body, env, out)
        except LangException:
            eval_block(stmt.handler, env, out)
    elif isinstance(stmt, RaiseStmt):
        val = eval_expr(stmt.expr, env)
        raise LangException(val)
    elif isinstance(stmt, NonlocalStmt):
        for name in stmt.names:
            env.declare_nonlocal(name)
    elif isinstance(stmt, ImportStmt):
        import_module(stmt.module, env)
    elif isinstance(stmt, ReturnStmt):
        val = eval_expr(stmt.expr, env)
        raise ReturnException(val)
    elif isinstance(stmt, BreakStmt):
        raise BreakException()
    elif isinstance(stmt, ContinueStmt):
        raise ContinueException()
    elif isinstance(stmt, ExprStmt):
        eval_expr(stmt.expr, env)
    else:
        raise RuntimeError("unknown statement")

def eval_expr(expr, env):
    if isinstance(expr, IntLit):
        return expr.value
    if isinstance(expr, StringLit):
        return expr.value
    if isinstance(expr, ListLit):
        return [eval_expr(e, env) for e in expr.elements]
    if isinstance(expr, DictLit):
        d = {}
        for k_expr, v_expr in expr.items:
            k = eval_expr(k_expr, env)
            v = eval_expr(v_expr, env)
            d[k] = v
        return d
    if isinstance(expr, Var):
        return env.get_var(expr.name)
    if isinstance(expr, Index):
        seq_val = eval_expr(expr.seq, env)
        idx_val = eval_expr(expr.index, env)
        try:
            return seq_val[idx_val]
        except Exception as e:
            raise RuntimeError(f"index error: {e}")
    if isinstance(expr, SliceIndex):
        seq_val = eval_expr(expr.seq, env)
        start = eval_expr(expr.start, env) if expr.start is not None else None
        stop  = eval_expr(expr.stop, env) if expr.stop is not None else None
        step  = eval_expr(expr.step, env) if expr.step is not None else None
        try:
            return seq_val[slice(start, stop, step)]
        except Exception as e:
            raise RuntimeError(f"slice error: {e}")
    if isinstance(expr, Attr):
        obj = eval_expr(expr.obj, env)
        name = expr.name
        if isinstance(obj, InstanceObject):
            if name in obj.fields:
                return obj.fields[name]
            val = class_lookup_attr(obj.cls, name)
            if val is not None:
                return val
            m = class_lookup_method(obj.cls, name)
            if m is not None:
                return m
            raise RuntimeError(f"attribute {name} not found")
        if isinstance(obj, ClassObject):
            val = class_lookup_attr(obj, name)
            if val is not None:
                return val
            m = class_lookup_method(obj, name)
            if m is not None:
                return m
            raise RuntimeError(f"class attribute {name} not found")
        if isinstance(obj, ModuleObject):
            m_env = obj.env
            if name in m_env.vars:
                return m_env.vars[name]
            if name in m_env.funcs:
                return m_env.funcs[name]
            if name in m_env.classes:
                return m_env.classes[name]
            raise RuntimeError(f"module attribute {name} not found")
        raise RuntimeError("attribute access only supported on objects")
    if isinstance(expr, MethodCall):
        obj = eval_expr(expr.obj, env)
        name = expr.name
        if isinstance(obj, list):
            args = [eval_expr(a, env) for a in expr.args]
            if name == "append":
                if len(args) != 1:
                    raise RuntimeError("list.append needs 1 arg")
                obj.append(args[0])
                return None
            if name == "pop":
                if len(args) == 0:
                    return obj.pop()
                if len(args) == 1:
                    return obj.pop(args[0])
                raise RuntimeError("list.pop takes at most 1 arg")
            if name == "sort":
                if len(args) != 0:
                    raise RuntimeError("list.sort takes no args")
                obj.sort()
                return None
            raise RuntimeError(f"unsupported list method {name}")
        if isinstance(obj, dict):
            args = [eval_expr(a, env) for a in expr.args]
            if name == "keys":
                if args:
                    raise RuntimeError("dict.keys takes no args")
                return list(obj.keys())
            if name == "values":
                if args:
                    raise RuntimeError("dict.values takes no args")
                return list(obj.values())
            if name == "items":
                if args:
                    raise RuntimeError("dict.items takes no args")
                return list(obj.items())
            if name == "get":
                if len(args) != 1:
                    raise RuntimeError("dict.get needs 1 arg")
                return obj.get(args[0])
            raise RuntimeError(f"unsupported dict method {name}")
        if isinstance(obj, InstanceObject):
            fn = class_lookup_method(obj.cls, name)
            if fn is None:
                raise RuntimeError(f"unknown method {name} on {obj.cls.name}")
            return call_method(obj, fn, expr.args, env)
        if isinstance(obj, ModuleObject):
            fn = obj.env.funcs.get(name)
            if fn is None:
                raise RuntimeError(f"unknown function {name} in module {obj.name}")
            return call_function(fn, expr.args, env)
        raise RuntimeError(f"method {name} not supported on type {type(obj).__name__}")
    if isinstance(expr, BinOp):
        left = eval_expr(expr.left, env)
        right = eval_expr(expr.right, env)
        op = expr.op
        if op in ("+", "-", "*", "/"):
            if op == "+":
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
        if expr.name == "range":
            if len(expr.args) != 1:
                raise RuntimeError("range() supports exactly 1 arg here")
            stop = eval_expr(expr.args[0], env)
            return range(int(stop))
        if expr.name == "len":
            if len(expr.args) != 1:
                raise RuntimeError("len() needs 1 argument")
            val = eval_expr(expr.args[0], env)
            try:
                return len(val)
            except TypeError:
                raise RuntimeError("object has no len()")

        try:
            fn = env.get_func(expr.name)
            return call_function(fn, expr.args, env)
        except NameError:
            pass
        try:
            cls = env.get_class(expr.name)
            return call_class(cls, expr.args, env)
        except NameError:
            pass
        try:
            val = env.get_var(expr.name)
            if isinstance(val, FunctionObject):
                return call_function(val, expr.args, env)
            if isinstance(val, ClassObject):
                return call_class(val, expr.args, env)
        except NameError:
            pass
        raise NameError(f"undefined function or class or variable {expr.name}")

    raise RuntimeError("unknown expression")

# =========================
# JIT helpers
# =========================

def can_jit_expr(expr, params):
    if isinstance(expr, IntLit):
        return True
    if isinstance(expr, Var):
        return expr.name in params
    if isinstance(expr, BinOp) and expr.op in ("+", "-", "*", "/"):
        return can_jit_expr(expr.left, params) and can_jit_expr(expr.right, params)
    return False

def emit_python_expr(expr):
    if isinstance(expr, IntLit):
        return str(expr.value)
    if isinstance(expr, Var):
        return expr.name
    if isinstance(expr, BinOp):
        left = emit_python_expr(expr.left)
        right = emit_python_expr(expr.right)
        op = expr.op
        if op == "/":
            op = "//"
        return f"({left} {op} {right})"
    raise RuntimeError("unsupported expression for JIT")

def maybe_jit_compile(fn):
    if fn.jit_impl is not None:
        return
    if len(fn.body) != 1 or not isinstance(fn.body[0], ReturnStmt):
        return
    expr = fn.body[0].expr
    if not can_jit_expr(expr, fn.params):
        return
    expr_code = emit_python_expr(expr)
    params_code = ", ".join(fn.params)
    src = f"lambda {params_code}: {expr_code}"
    try:
        fn.jit_impl = eval(src, {})
    except Exception:
        fn.jit_impl = None

# =========================
# Callers (functions / methods / classes)
# =========================

def call_function(fn, args_exprs, env):
    fn.call_count += 1
    if fn.call_count >= JIT_THRESHOLD and fn.jit_impl is None:
        maybe_jit_compile(fn)

    if len(args_exprs) != len(fn.params):
        raise RuntimeError(f"{fn.name} expected {len(fn.params)} args, got {len(args_exprs)}")

    arg_values = []
    annotations = fn.annotations or {}
    for name, expr_arg in zip(fn.params, args_exprs):
        val = eval_expr(expr_arg, env)
        expected_type_name = annotations.get(name)
        if expected_type_name is not None:
            tp = TYPE_MAP.get(expected_type_name)
            if tp is not None and not isinstance(val, tp):
                raise RuntimeError(f"type error in call to {fn.name}: param {name} expected {expected_type_name}, got {type(val).__name__}")
        arg_values.append((name, val))

    if fn.jit_impl is not None:
        ordered = [v for _, v in arg_values]
        return fn.jit_impl(*ordered)

    local = Env(parent=fn.env)
    for name, val in arg_values:
        local.set_var(name, val)
    try:
        eval_block(fn.body, local, out=[])
        return None
    except ReturnException as r:
        return r.value

def call_method(instance, fn, args_exprs, env):
    fn.call_count += 1
    if fn.call_count >= JIT_THRESHOLD and fn.jit_impl is None:
        maybe_jit_compile(fn)

    if not fn.params:
        raise RuntimeError("method must have at least one parameter (self)")
    self_name = fn.params[0]
    expected = len(fn.params) - 1
    if len(args_exprs) != expected:
        raise RuntimeError(f"{fn.name} expected {expected} args, got {len(args_exprs)}")

    annotations = fn.annotations or {}
    arg_values = []

    expected_type_name = annotations.get(self_name)
    if expected_type_name is not None:
        pass
    arg_values.append((self_name, instance))

    for name, expr_arg in zip(fn.params[1:], args_exprs):
        val = eval_expr(expr_arg, env)
        expected_type_name = annotations.get(name)
        if expected_type_name is not None:
            tp = TYPE_MAP.get(expected_type_name)
            if tp is not None and not isinstance(val, tp):
                raise RuntimeError(f"type error in call to {fn.name}: param {name} expected {expected_type_name}, got {type(val).__name__}")
        arg_values.append((name, val))

    if fn.jit_impl is not None:
        ordered = [v for _, v in arg_values]
        return fn.jit_impl(*ordered)

    local = Env(parent=fn.env)
    for name, val in arg_values:
        local.set_var(name, val)
    try:
        eval_block(fn.body, local, out=[])
        return None
    except ReturnException as r:
        return r.value

def call_class(cls, args_exprs, env):
    inst = InstanceObject(cls, fields=dict(cls.attributes))
    init = class_lookup_method(cls, "__init__")
    if init is not None:
        call_method(inst, init, args_exprs, env)
    return inst

# =========================
# Import system
# =========================

def import_module(name, env):
    if name in MODULE_CACHE:
        env.set_var(name, MODULE_CACHE[name])
        return
    path = name + ".pa"
    try:
        src = open(path).read()
    except FileNotFoundError:
        raise RuntimeError(f"cannot import {name}: {path} not found")
    tokens = lex(src)
    parser = Parser(tokens)
    prog = parser.parse_program()
    module_env = Env()
    module_out = []
    eval_block(prog.stmts, module_env, module_out)
    mod = ModuleObject(name, module_env)
    MODULE_CACHE[name] = mod
    env.set_var(name, mod)

# =========================
# Main
# =========================

def main():
    if len(sys.argv) != 2:
        print("usage: pathon main.pa")
        sys.exit(1)

    src = open(sys.argv[1]).read()
    tokens = lex(src)
    parser = Parser(tokens)
    prog = parser.parse_program()

    out_text = eval_program(prog)
    msg = out_text.encode()

    code = build_print(msg)
    binfile = elf64(code, msg)

    os.makedirs("build", exist_ok=True)
    out = "build/main"
    open(out, "wb").write(binfile)
    os.chmod(out, 0o755)

    proc = subprocess.run([out], capture_output=True, text=True)
    print(proc.stdout, end="")
    sys.exit(proc.returncode)

if __name__=="__main__":
    main()
