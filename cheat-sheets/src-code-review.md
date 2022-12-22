
## Reference

 Generic:

 [OWASP Code Review Guide](https://www.owasp.org/index.php/OWASP_Code_Review_Guide_Table_of_Contents) | [OWASP Secure Coding Practices - Quick Reference Guide](https://www.owasp.org/index.php/OWASP_Secure_Coding_Practices_-_Quick_Reference_Guide)

 C/C++: 
 
 [CERT C Secure Coding Standard](https://www.securecoding.cert.org/confluence/display/c/SEI+CERT+C+Coding+Standard) | [SEI CERT C++ Coding Standard](https://www.securecoding.cert.org/confluence/pages/viewpage.action?pageId=637)

 [libc reference](res/libc-reference.pdf) | [C specification](res/c-specification.pdf)

 [C++ Developer Guidance for Speculative Execution Side Channels](https://docs.microsoft.com/en-us/cpp/security/developer-guidance-speculative-execution)

 Java:

 [Oracle Secure Coding Guidelines](http://www.oracle.com/technetwork/java/seccodeguide-139067.html) | [CERT: Java Coding Guidelines](https://www.securecoding.cert.org/confluence/display/java/Java+Coding+Guidelines)

 Approach/reports/documenting:

 [Mozilla code audit reports](https://wiki.mozilla.org/MOSS/Secure_Open_Source/Completed) | [Qualys Reports](https://www.qualys.com/research/security-advisories/)

## Static analysis tooling

### base

```
flawfinder
cppcheck
clang analyzer
gcc -Wall -Werror -pedantic -std=[c99 | c1x | c11]
```

### CodeQL

    https://frycos.github.io/vulns4free/2022/12/02/rce-in-20-minutes.html

### native code review

```
https://github.com/CoolerVoid/heap_detective
semgrep rules for C/C++:
https://github.com/0xdea/semgrep-rules
```

## Source code review tips/best practices

### source code navigation

**Setting up cscope & ctags**

```
# setup ctags & cscope
wget http://cscope.sourceforge.net/cscope_maps.vim
mkdir -p /home/fuzz/.vim/plugin/
cp cscope_maps.vim ~/.vim/plugin/

# In src/ dir:
ctags -R ./*
find ./ -name '*.c' -o -name '*.cpp' > cscope.files
cscope -q -R -b -i cscope.files
```

**Usage (cscope)**

```
's'   symbol: find all references to the token under cursor (<C-\>s)
'g'   global: find global definition(s) of the token under cursor
'c'   calls:  find all calls to the function name under cursor
't'   text:   find all instances of the text under cursor
'e'   egrep:  egrep search for the word under cursor
'f'   file:   open the filename under cursor
'i'   includes: find files that include the filename under cursor
'd'   called: find functions that function under cursor calls
```

**Calculating C LoC (removes comments and blank lines)**

    find ./ -name "*.[ch]" | xargs cat | grep -v '^[[:space:]]*$' | grep -v '^[[:space:]]*\*.*$' | grep -v '^[[:space:]]*//.*$' | wc -l

**code formatting tools**

    http://clang.llvm.org/docs/ClangFormat.html

**Line numbers**

```
# show in vim:
:set number

# add (for real to the file):
:%s/^/\=line('.').". "
```

**Block commenting**

    ctrl-V
    select
    shift-i
    ESC
    https://stackoverflow.com/a/1676690
