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
    "while": "WHILE",
    "for": "FOR",
    "in": "IN",
    "break": "BREAK",
    "continue": "CONTINUE",
}

def lex_line(line):
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
        }
        if c in single:
            tokens.append(Token(single[c], c))
            i += 1
            continue
        raise SyntaxError(f"unexpected character {c!r}")
    return tokens

def lex(src):
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

@dataclass
class Assign:
    name: str
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
class FuncDef:
    name: str
    param: object
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
    arg: object

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
        if self.cur.type == "IDENT" and self.peek().type == "EQ":
            return self.parse_assign()
        expr = self.parse_expr()
        return ExprStmt(expr)

    def parse_print(self):
        self.eat("PRINT")
        self.eat("LPAREN")
        expr = self.parse_expr()
        self.eat("RPAREN")
        return PrintStmt(expr)

    def parse_assign(self):
        name = self.cur.value
        self.eat("IDENT")
        self.eat("EQ")
        expr = self.parse_expr()
        return Assign(name, expr)

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
        param = None
        if self.cur.type == "IDENT":
            param = self.cur.value
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
        return FuncDef(name, param, body)

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
# Interpreter
# =========================

class ReturnException(Exception):
    def __init__(self, value):
        self.value = value

class BreakException(Exception):
    pass

class ContinueException(Exception):
    pass

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
    param: object
    body: list
    env: Env

def eval_block(stmts, env, out):
    for s in stmts:
        eval_stmt(s, env, out)

def eval_program(prog):
    env = Env()
    out = []
    eval_block(prog.stmts, env, out)
    return "".join(out)

def eval_stmt(stmt, env, out):
    if isinstance(stmt, Assign):
        val = eval_expr(stmt.expr, env)
        env.set_var(stmt.name, val)
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
    elif isinstance(stmt, FuncDef):
        fn = FunctionObject(stmt.name, stmt.param, stmt.body, env)
        env.set_func(stmt.name, fn)
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
    if isinstance(expr, Var):
        return env.get_var(expr.name)
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
            if expr.arg is None:
                raise RuntimeError("range() needs 1 argument for now")
            stop = eval_expr(expr.arg, env)
            return range(int(stop))
        fn = env.get_func(expr.name)
        local = Env(parent=fn.env)
        if fn.param is not None:
            if expr.arg is not None:
                arg_val = eval_expr(expr.arg, env)
            else:
                arg_val = None
            local.set_var(fn.param, arg_val)
        try:
            eval_block(fn.body, local, out=[])
            return None
        except ReturnException as r:
            return r.value
    raise RuntimeError("unknown expression")

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
