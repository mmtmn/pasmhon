pasmhon
```
                                                 ░██                              
░████████   ░██████    ░███████  ░█████████████  ░████████   ░███████  ░████████  
░██    ░██       ░██  ░██        ░██   ░██   ░██ ░██    ░██ ░██    ░██ ░██    ░██ 
░██    ░██  ░███████   ░███████  ░██   ░██   ░██ ░██    ░██ ░██    ░██ ░██    ░██ 
░███   ░██ ░██   ░██         ░██ ░██   ░██   ░██ ░██    ░██ ░██    ░██ ░██    ░██ 
░██░█████   ░█████░██  ░███████  ░██   ░██   ░██ ░██    ░██  ░███████  ░██    ░██ 
░██                                                                               
░██     
```
python2asm
```
▄▄▄▄  ▄▄ ▄▄ ▄▄▄▄▄▄ ▄▄ ▄▄  ▄▄▄  ▄▄  ▄▄   ████▄    ▄▄▄   ▄▄▄▄ ▄▄   ▄▄ 
██▄█▀ ▀███▀   ██   ██▄██ ██▀██ ███▄██    ▄██▀   ██▀██ ███▄▄ ██▀▄▀██ 
██      █     ██   ██ ██ ▀███▀ ██ ▀██   ███▄▄   ██▀██ ▄▄██▀ ██   ██ 
```
```
results per execution:

python3: avg 7523.9 us   std 991.9 us

pasmhon: avg 102.8 us   std 22.7 us

speedup: 73.20814812582314
```

# roadmap


**Phase 1: Core Language Features**

- [x] print
- [x] variables
- [x] math
- [x] functions
- [x] conditions
- [x] if statements
- [x] loops
- [x] lists and dictionaries
- [x] oop (single inheritance)
- [x] exceptions (try/except)
- [x] slices
- [x] closures and nonlocal
- [x] import system
- [x] bytecode VM
- [x] JIT
- [x] static typing
- [x] single line comments
- [x] multi line comments
- [x] kwargs
- [x] defaults
- [x] varargs
- [x] lambdas
- [x] list comprehensions
- [x] dict comprehensions
- [x] yield (basic)
- [x] generator expressions
- [x] async / await (syntax + minimal execution)
- [x] with statements (simple context managers)
- [x] enumerate, zip, map, filter
- [x] real slicing semantics (full Python behavior)
- [x] unicode correctness (parsing + string ops)


**Phase 2: Advanced Language Constructs**

- [ ] multiple inheritance
- [ ] C3 linearization (real MRO)
- [ ] method resolution parity with Python
- [ ] super()
- [ ] class attributes vs instance attributes parity


**Phase 3: Python Data Model**

- [ ] descriptor protocol  
  - __get__  
  - __set__  
  - __delete__
- [ ] bound/unbound method behavior  
- [ ] getattr, setattr, delattr  
- [ ] __getattribute__ override

- [ ] operator overloading  
  - __add__, __radd__, __mul__, etc  
  - rich comparisons  

- [ ] numeric tower behavior  
- [ ] __iter__, __next__, full iterator protocol  
- [ ] __len__, __bool__, __contains__  
- [ ] __getitem__, __setitem__, __delitem__  
- [ ] __enter__, __exit__ (full with-statement behavior)
- [ ] __call__
- [ ] __str__, __repr__


**Phase 4: Exceptions and Types**

- [ ] real exception classes  
- [ ] exception hierarchy  
- [ ] except TypeError: must match subclasses  
- [ ] raise from  
- [ ] traceback object model (optional but real Python has it)


**Phase 5: Full Class System**

- [ ] metaclasses  
- [ ] type as a class  
- [ ] class creation path:  
  meta = type(base)  
  cls = meta(name, bases, dict)

- [ ] __new__ vs __init__  
- [ ] class decorators  
- [ ] function decorators  
- [ ] @property  
- [ ] classmethod / staticmethod (descriptor-based)


**Phase 6: Runtime and Execution Semantics**

- [ ] proper generators (stack suspension)  
- [ ] send(), throw(), close()  
- [ ] async event loop (if you want real async)

- [ ] closures with real cell objects  
- [ ] locals(), globals(), variable scoping parity  
- [ ] eval() and exec()  
- [ ] dynamic introduction of variables  


**Phase 7: Standard Library Compatibility**

- [ ] builtins module  
- [ ] sys module (partial)  
- [ ] importlib-like loader  
- [ ] sys.path, package structure, __init__.pa  
- [ ] circular imports  
- [ ] relative imports  


**Phase 8: Performance + Memory Model**

- [ ] reference counting  
- [ ] cyclic GC  
- [ ] weakrefs  
- [ ] object finalization rules  

**Phase 9: Assembly + Native Code Polish**

- [ ] fast path for numeric ops  
- [ ] inline caches for attribute lookup  
- [ ] specialized bytecodes (Python 3.11 style)  
- [ ] peephole optimizations  
- [ ] inliner for small functions  
- [ ] constant folding


# how to use it:

- add an alias to `./pasmhon.py` make sure to give it permissions with `chmod +x pashmhon.py` (for this example we'll say the alias to this file is pa)
- run `pa test.pa` on the terminal
- get the best optimal performance boost possible

# but why?

- the intent is to go one language at a time, with the intent of a universal assembly compiler
- asm is my **favorite** programming language and this is my way of having fun
