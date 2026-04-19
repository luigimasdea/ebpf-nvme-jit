OUTPUT_ARCH( "riscv" )
ENTRY( _start )

MEMORY
{
  /* Reserved RAM block (AMP Mode) */
  FIRMWARE (rwx) : ORIGIN = 0x222000000, LENGTH = 1M
  STACK    (rw)  : ORIGIN = 0x222100000, LENGTH = 1M
  JIT_BUF  (rwx) : ORIGIN = 0x222200000, LENGTH = 2M
  QUEUES   (rw)  : ORIGIN = 0x222400000, LENGTH = 1M
  PAYLOAD  (rw)  : ORIGIN = 0x222500000, LENGTH = 11M
}

SECTIONS
{
  . = ORIGIN(FIRMWARE);

  .text : {
    KEEP(*(.init))           /* Boot code MUST be first */
    *(.text .text.*)         /* C code */
    *(.rodata .rodata.*)     /* Read-only data (strings, constants) */
  } > FIRMWARE

  .data : {
    . = ALIGN(8);
    __global_pointer$ = . + 0x800; /* Optimization for RISC-V gp register */
    *(.data .data.*)
    *(.sdata .sdata.*)
  } > FIRMWARE

  .bss : {
    . = ALIGN(8);
    __bss_start = .;
    *(.bss .bss.*)
    *(.sbss .sbss.*)
    . = ALIGN(8);
    __bss_end = .;
  } > FIRMWARE

  /* Symbols for the boot.S entry script */
  _stack_top = ORIGIN(STACK) + LENGTH(STACK);
}
