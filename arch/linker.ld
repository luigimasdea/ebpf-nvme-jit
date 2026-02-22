OUTPUT_ARCH( "riscv" )
ENTRY( _start )

MEMORY
{
  /* QEMU -machine virt inizia la RAM a 0x80000000 */
  RAM (rwx) : ORIGIN = 0x80000000, LENGTH = 128M
}

SECTIONS
{
  . = 0x80000000;
  .text : {
    *(.init)
    *(.text)
  } > RAM
  
  .data : { *(.data) } > RAM
  .bss : { *(.bss) } > RAM
}
