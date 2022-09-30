# 9.22 0th
```sh
$ ls -l big
-rw-r--r-- 1 eggert faculty 9223382036854775000 Sep 22 11:31 big
$ grep x big
$ time grep x big
real 0m0.009s
```
- `grep` scans at $10^{21}$ bytes/s (8 Zb/s) searching for an existent line in the file
- so it has to be doing smth other than sequentially searching thru the file
- "grep cheats"
  - "i know it cheats cuz i put the code in it" - eggert 2022
- "i hope you gain the intuition to know when is it ok to cheat and when is it not"

- paul eggert
- https://web.cs.ucla.edu/classes/fall22/cs111
- prereqs: cs32  <- c++, algs, data structurues      \         / cs118 networking
             33  <- computer org, machine code, etc. |-> cs111 - ...
             35l <- shell, python, scripting, ...    /         \ ...
- cs131 programming languages
- cs151b architecture
- textbooks
  - ad os 3ep  (2018)
  - sk systems (2009)

## whats a system
- *oxford english dictionary* (1928)
  - i.  an organized or connected group of objects
  - ii. a set of principles, etc.; a scheme, method
  - from ancient greek $\sigma\iota\sigma\tau\eta\mu\alpha$(roots, "set up w")
- *principle of computer science design: an introduction* (2009)
  - smth that ops in an env and the boundary betw the 2 is called the interface
    - interface v important
    - system built from a lot of subsystems
    - standard design: decompose big system
    - often time its useful to have multiple views of the same system
      - sometimes we can look at the system from a diff viewpoint and come up w a completely different set of subsystems

## operating system
- *american heritage dictionary* (2000)
  - software designed to control the hardware of a specific data processing system in order to allow users and application programs to make use of it
    - claims os is very system dependent, not true
- *encarta* (2007)
  - master control program in a computer
- *wikipdeia* (2016/8)
  - system software that manages computer, hardware, software resources, and provides common services for computer programs

## goals of an operating system
- protection (of apps, data, ...)
- performance (from users view)
- utilization (from check-writers view)
- robustness
  - does this operating system do well when given problems out of the ordinary
- flexibility
- simplicity / ease of use
- portability w diff hardware
- scalability
- safety

## what are our main tools?
- abstraction + modularity
  - abstraction: look at the big pic of the system from a particular viewpoint and discard details to understand everything abt that aspect of the system
  - modularity: splitting up a big problem into little problems
    - since the diff in writing a program scales worse than linearly, 
  - interface vs implementation
  - mechanisms vs policy
    - policy: high level concept in which u say what u want
      - "i want my interactive processes to have higher priority than background batches"
    - mechanism: how u actually get that stuff to work
- measurements + monitoring
  - measurements: measure how well ur system is working
    - performance + correctness
  - monitoring: monitor measurements, do smth w them
- *operating systems: three easy pieces*: main problems in os
  - virtualization: how to build efficient + effective virtual systems
  - concurrency: interacting, simultaneous tasks
  - persistence: data survive failures in hardware, software
  - more
    - security

## a bad os interface
```c
char* readline(int fd);
```
- assumes infinite resources



# 9.23 0f
- kernel: lowest level of the os
  - decides what resources are available to apps (thus protecting the system)
  - provides layer of abstraction so that apps dont have to deal w hardware
  - TODO: see notes.md.old

## kernel modules
- are pieces of code that can be loaded and unloaded into the kernel upon demand
- they extend the functionality of the kernel without the need to reboot the system
- why not just add all the new functionalities into the kernel image
  - would be bloated
  - security implications
- modules are stored in `/usr/lib/modeuls/kernel_release`
- to see what kernel modules are currently loaded use
```sh
lsmod
```
```sh
cat /proc/modules
```
- example
```c
#include <linux/module.h> /* needed by all modules */

#include <linux/kernel.h> /* needed for KERN_INFO */

int init_module(void) {
  printk(KERN_INFO "hello world 1.\n");
  return 0;
}

void cleanup_module(void) {
  printk(KERN_INFO "goodbye world 1.\n");
}
```
- `printk`
  - was not meant to communicate info to user
- to load a module: `sudo insmod <module_name> [args]`
```sh
sudo insmod proc_count.ko
```
- to unload a module: `sudo rmmod <module_name>`
```sh
sudo rmmod proc_count
```

# 9.27 1t

## simple os architecture
- TODO: insert pic
- user mode code: apps, libraries / c-lib
- kernel mode: you can execute instructions here
  - e.g. `inb`
  - kernel-app interface: "imaginary instructions" that are not real
    - x84-64 instructions `ret`: "`rip = *(--rsp)`" in user mode
    - `syscall 35`: "`os[35]()`" in kernel mode
      - `syscall`s cannot be called in user mode, kernel will figure it out

```c
char *readline(int fd)
```
- `fd`
  - `0` - `stdin`
  - `1` - `stdout`
  - `2` - `stderr`
  - `>2` - other files
- points to a newly allocated buffer, e.g. `"ab\0xyz\n"`
- problems
  - unbounded cost
  - allocates memory for the application
  - large potential for memory leaks & bad pointers
    - probles with giving the job to kernel
      - force same memory mgmt on all apps
      - syscall overhead

```c
ssize_t read(int fd, void *buf, size_t bufsize);
```
- it is now the applications job to figure allocation out, kernel doesnt care
- there is now a limit on read size
- comes at a cost: a program that counts the number of lines in a file becomes more complicated although it has nice properties for the kernel

## problems with designing operating systems
- waterbed effect (tradeoffs): general problem in systems
- incommensurate scaling
  - economies of scale (pin factory)
    - if u just want a few pins then just go to local blacksmith
    - if u want 10mil pins u should create a pin factory
  - diseconomies of scale (star network)
- emergent properties (as u scale)
  - qualitative instead of quantitative changes
  - ucla in school network used for music pirating
- propagation of effects
  - 2 features that independently work may not work when combined
  - e.g. msft invented shift-jis to encode japanese characters
    - 2-byte encoding w top bit on = $2^15$ characters
    - other feature: file names `C:\abc\def\ghi.txt`
    - combination doesnt work because 2nd byte of shift-jis character can be anything (could just happen to be `'\'`)
    - fixed by moving into kernel (complicating the os)
- complexity
  - moores law

## app: count words in a file
- TODO: add pic
- power button = count number of words and put it on screen
- historically called a standalone program
  - operates without benefits of an os
- modern desktop
  - TODO: add pic

## uefi: unified extensible firmware interface
- os-independent way to boot
- efi format for **bootloaders**
  - bootloader: find a program in 2ndary storage, copy it into ram and `jmp` to it
  - can be chained, not uncommon to see 3 or 4 chained bootloaders
    - for portability and stuff
    - each bootloader can be more complicated than the next one until one that knows how to boot linux
- guid: globally unique identifier
  - for partitions
  - 128-bit integer
- guid partion table
- uefi boot manager (in firmware)
  - read only but configurable via parameters in some sort of nvram (nonvolatile ram)
 - can read gpt tables
  - can access files in vfat format etc
  - can run code in efi format
  - 6 phases

## coreboot
- more hardware-specific / lower level
- no large boot manager (but a small one)
- 4 phases
  - test rom (find out where it is) + flash / disk
  - test ram, early initialization of chipset
  - ram stage: init cpu, chipset, motherboard, devices, etc
  - load payload

## intel core i3-9100
- supports an older, simpler way of booting
- 6 mib l3 cache, 3.6 ghz + 4 gib ddr3 sdram + 1 tb flash sata + intel uhd graphic
- sata: serial ata
  - 7-conductor connector
  - ata (pata): advance technology attachment (16-bit connector in parallel)
    - sequentization is the bane of parallel
  - before ata = ide: integrated drive electronics (western digital, 1986)
- x86 boot procedure
  - 1 mib of physical ram cpu can access
    - cpu starts off in real mode = no virtual memory
  - initial program counter `ip` points to rom @ `0xffff0` $= 2^{20} - 16$
  - program in rom = bios: basic input output system
    - "horrible misdesign"
    - originally user apps ran in real mode, calling subroutines in bios
      - only protection is rom being read only
    - library + kernel + mini os basically
    - bios tries to do the 4 steps in coreboot
      - run in cache only mode
      - step 4: looks for a device containing a particular bit pattern in its first 512 bytes (sector) (mbr: master boot record, 446 bytes of x86 machine code, 64 bytes of partition table (list of 4 pieces of drive, takes role of gpt), 2 bytes of signature `0x55 0xaa` or `0xaa55`)

# 9.29 1th

## less modular os
- one happy program
- uses function calls
- count lines in a file only via function calls + machine instructions at lowest level
- last time we got 426 of bytes of machine code into `0x7c00`
- file is in flash drive
- bootloader reads word count program, say 20 sectors (of 512 bytes), into ram, say `0x1000`
```c
static void read_ide_sector(long secno, char *addr) {
  while ((inb(0x1f7) & 0xc0) != 0x40) continue;
  outb(0x1f2, 1);
  outb(0x1f3, secno);
  outb(0x1f4, secno >> 8);
  outb(0x1f5, secno >> 16);
  outb(0x1f6, secno >> 24);
  outb(0x1f7, 0x20);
  while ((inb(0x1f7) & 0xc0) != 0x40) continue;
  insl(0x1f0, addr, 128);
}
```
- `inb` reads from io registers
- `0x1f7`: status + control
- first `while` loop waits for drive to be ready
- `insl`: "insert long", read 128 words (512 bytes) from `1f0` to `addr`
```c
static unsigned char inb(unsigned short port) {
  unsigned char data;
  asm volatile("inb %0, %1" : "=a" (data) : "dN" (port));
  return data;
}
```

## i/o
- programmed i/o (pio): special instructions for io
- memory-mapped i/o: more popular, use ordinary load / store instructions `mov_ _`
- intel: flash drive uses pio, monitor uses memory-mapped
```c
void write_integer_to_console(long n) {
  unsigned short *p = (unsigned short*) 0xb8014;
  while (n) {
    *p-- = (7 << 8) | ('0' + n % 10);
    n /= 10;
  }
}
```
- at `0xb8000`, 2 bytes per char, 1st byte being format (7: gray on black), 2nd byte being ascii, $80 \times 25$ grid
- code above prints 
```c
static int isalpha(int x) { return 'a' <= x && x <= 'z' || 'A' <= x && x <= 'Z'; }

void main(void) {
  long words = 0;
  bool in_word = false;
  long secno = 100'000;
  for (;; ++secno) {
    char buf[512];
    read_ide_sector(secno, buf);
    for (int j = 0; j < 512; ++j) {
      if (!buf[j]) {
        write_integer_to_console(words + in_word);
        while (true);
      }
      bool this_alpha = isalpha((unsigned char) buf[j]);
      words += in_word & ~this_alpha;
      in_word = this_alpha;
    }
  }
}
```
- performance issues
  - read 1 sector at a time: change to 255 sectors
  - bus contention (controller $\leftrightarrow$ cpu, cpu $\leftrightarrow$ ram): dma (direct memory access), controller $\leftrightarrow$ ram, cpu sends instruction to controller telling where to copy data to
  - cpu and controller doing work disjointly: double buffering&mdash;cpu issues command to read sector $n + 1$ *then* cpu counts words in sector $n$ = overlapping work
