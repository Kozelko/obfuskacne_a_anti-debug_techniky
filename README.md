# Obfuskačné a Anti-Debug Techniky

Projekt z predmetu BIT - implementácia compile-time XOR obfuskácie a anti-debug techník pre Windows a Linux.

## Disclaimer

**Tento projekt je určený výhradne na vzdelávacie účely.**

Implementované techniky slúžia na demonštráciu a pochopenie ochranných mechanizmov softvéru. Použitie týchto techník na škodlivé účely, obchádzanie bezpečnostných opatrení bez autorizácie, alebo v rozpore so zákonmi je prísne zakázané.

Autor nenesie zodpovednosť za akékoľvek zneužitie tohto kódu.

## Popis projektu

Projekt implementuje:
- **Compile-time XOR obfuskáciu** - citlivé reťazce sú zašifrované počas kompilácie
- **Anti-debug techniky pre Windows** - IsDebuggerPresent, PEB->BeingDebugged, CheckRemoteDebuggerPresent, NtQueryInformationProcess
- **Anti-debug techniky pre Linux** - ptrace, TracerPid, parent process, LD_PRELOAD detekcia, cmdline kontrola

## Požiadavky

#### Windows
- MinGW-w64 (g++ s podporou C++14)

#### Linux
- GCC/G++ s podporou C++14
- Voliteľne: GDB, strace na testovanie

## Kompilácia

#### Linux
```bash
g++ main.cpp -o linux_antidebug -std=c++14
```

#### Windows
```bash
g++ main.cpp -o windows_antidebug.exe -std=c++14
```


## Spustenie

#### Normálne spustenie
```bash
# Linux
./linux_antidebug

# Windows
windows_antidebug.exe
```

Program vykoná anti-debug kontroly a ak nie je detekovaný debugger, zobrazí skutočný flag.

#### Testovanie detekcie debuggera

**Linux (GDB):**
```bash
gdb ./linux_antidebug
(gdb) run
```

**Linux (strace):**
```bash
strace -o /dev/null ./linux_antidebug
```

**Windows (x64dbg):**
Otvorte `windows_antidebug.exe` v x64dbg a spustite.


### Testovanie obfuskácie

Overenie, že reťazce nie sú viditeľné v binárke:
```bash
strings linux_antidebug | grep -i "flag"
# Výstup: žiadny (reťazce sú zašifrované)
```

## Dokumentácia

Kompletná dokumentácia vrátane:
- Analýzy implementovaných techník
- Postupov na obchádzanie ochranných mechanizmov
- Statickej analýzy v Ghidra
- Komparatívnej analýzy efektivity

Nachádza sa v súbore `dokumentacia.md`.

## Bypass techniky (zdokumentované v projekte)

#### Windows

| Technika                   | Bypass metóda                     |
| -------------------------- | --------------------------------- |
| IsDebuggerPresent          | Breakpoint + zmena RAX na 0       |
| PEB->BeingDebugged         | Patch hodnoty na offsete +0x2     |
| CheckRemoteDebuggerPresent | Breakpoint + zmena RAX na 0       |
| NtQueryInformationProcess  | Zmena `je` na `jmp` (patch skoku) |
| Všetky techniky            | ScyllaHide plugin                 |

#### Linux

| Technika         | Bypass metóda                             |
| ---------------- | ----------------------------------------- |
| ptrace           | `return (int)0` v GDB                     |
| TracerPid        | `return (int)0` v GDB (spoločne s ptrace) |
| Parent process   | `return (int)0` v GDB                     |
| Cmdline kontrola | `return (int)0` v GDB                     |
| LD_PRELOAD       | getenv() hook cez LD_PRELOAD              |
| strace           | Patch binárky (`xor eax, eax; ret`)       |

## Licencia

Tento projekt je poskytnutý "as is" bez akýchkoľvek záruk. Použitie na vlastné riziko.

## Autor

Peter Brandajský - Projekt BIT 2025
