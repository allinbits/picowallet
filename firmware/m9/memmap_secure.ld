/* Linker script for the M9 Secure image. Derived from pico-sdk's
 * memmap_default.ld; the divergences are:
 *
 *   - FLASH is bounded to firmware/m9/layout.h's M9_SECURE_FLASH_SIZE
 *     (512 KB) starting at M9_SECURE_FLASH_BASE (0x10000000).
 *   - RAM is bounded to M9_SECURE_SRAM_SIZE (128 KB) at
 *     M9_SECURE_SRAM_BASE (0x20000000).
 *   - The NSC veneer region (4 KB at end of Secure flash) gets its own
 *     output section, .nsc, so the cmse_nonsecure_entry symbols land
 *     there. SAU region 0 is set up by secure_stub.c to map exactly
 *     this range.
 *   - SCRATCH_X / SCRATCH_Y are *not* mapped here -- Secure runs from
 *     the main SRAM bank only; core0/core1 NS stacks live in the
 *     NS image's scratch banks.
 *
 * Everything else (vector layout, data copy table, picobin block) is
 * carried over verbatim. */

MEMORY
{
    FLASH(rx) : ORIGIN = 0x10000000, LENGTH = 0x0007F000   /* 508 KB; reserve last 4 KB for NSC */
    NSC(rx)   : ORIGIN = 0x1007F000, LENGTH = 0x00001000   /* 4 KB veneer region */
    RAM(rwx)  : ORIGIN = 0x20000000, LENGTH = 128k
}

ENTRY(_entry_point)

SECTIONS
{
    .flash_begin : {
        __flash_binary_start = .;
    } > FLASH

    .text : {
        __logical_binary_start = .;
        KEEP (*(.vectors))
        KEEP (*(.binary_info_header))
        __binary_info_header_end = .;
        KEEP (*(.embedded_block))
        __embedded_block_end = .;
        KEEP (*(.reset))
        *(.init)
        *libgcc.a:cmse_nonsecure_call.o
        *(EXCLUDE_FILE(*libgcc.a: *libc.a:*lib_a-mem*.o *libm.a:) .text*)
        *(.fini)

        *crtbegin.o(.ctors)
        *crtbegin?.o(.ctors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .ctors)
        *(SORT(.ctors.*))
        *(.ctors)
        *crtbegin.o(.dtors)
        *crtbegin?.o(.dtors)
        *(EXCLUDE_FILE(*crtend?.o *crtend.o) .dtors)
        *(SORT(.dtors.*))
        *(.dtors)

        . = ALIGN(4);
        PROVIDE_HIDDEN (__preinit_array_start = .);
        KEEP(*(SORT(.preinit_array.*)))
        KEEP(*(.preinit_array))
        PROVIDE_HIDDEN (__preinit_array_end = .);

        . = ALIGN(4);
        PROVIDE_HIDDEN (__init_array_start = .);
        KEEP(*(SORT(.init_array.*)))
        KEEP(*(.init_array))
        PROVIDE_HIDDEN (__init_array_end = .);

        . = ALIGN(4);
        PROVIDE_HIDDEN (__fini_array_start = .);
        *(SORT(.fini_array.*))
        *(.fini_array)
        PROVIDE_HIDDEN (__fini_array_end = .);

        *(.eh_frame*)
        . = ALIGN(4);
    } > FLASH

    .boot2 : {
        __boot2_start__ = .;
        *(.boot2)
        __boot2_end__ = .;
    } > FLASH
    ASSERT(__boot2_end__ - __boot2_start__ <= 256,
        "ERROR: Pico second stage bootloader must be no more than 256 bytes")

    .rodata : {
        *(EXCLUDE_FILE(*libgcc.a: *libc.a:*lib_a-mem*.o *libm.a:) .rodata*)
        *(.srodata*)
        . = ALIGN(4);
        *(SORT_BY_ALIGNMENT(SORT_BY_NAME(.flashdata*)))
        . = ALIGN(4);
    } > FLASH

    .ARM.extab : { *(.ARM.extab* .gnu.linkonce.armextab.*) } > FLASH
    __exidx_start = .;
    .ARM.exidx :  { *(.ARM.exidx*  .gnu.linkonce.armexidx.*) } > FLASH
    __exidx_end = .;

    . = ALIGN(4);
    __binary_info_start = .;
    .binary_info : {
        KEEP(*(.binary_info.keep.*))
        *(.binary_info.*)
    } > FLASH
    __binary_info_end = .;
    . = ALIGN(4);

    /* Non-Secure Callable veneer region. Functions marked with
     *   __attribute__((cmse_nonsecure_entry))
     * land here via the .gnu.sgstubs section the toolchain emits. SAU
     * region 0 covers exactly this range and grants NS read+execute. */
    .nsc : ALIGN(32) {
        __nsc_start = .;
        *(.gnu.sgstubs*)
        . = ALIGN(32);
        __nsc_end = .;
    } > NSC

    .ram_vector_table (NOLOAD) : { *(.ram_vector_table) } > RAM
    .uninitialized_data (NOLOAD) : {
        . = ALIGN(4);
        *(.uninitialized_data*)
    } > RAM

    .data : {
        __data_start__ = .;
        *(vtable)
        *(.time_critical*)
        *(.text*)
        . = ALIGN(4);
        *(.rodata*)
        . = ALIGN(4);
        *(.data*)
        *(.sdata*)
        . = ALIGN(4);
        *(.after_data.*)
        . = ALIGN(4);
        PROVIDE_HIDDEN (__mutex_array_start = .);
        KEEP(*(SORT(.mutex_array.*)))
        KEEP(*(.mutex_array))
        PROVIDE_HIDDEN (__mutex_array_end = .);
        *(.jcr)
        . = ALIGN(4);
    } > RAM AT> FLASH

    .tdata : {
        . = ALIGN(4);
        *(.tdata .tdata.* .gnu.linkonce.td.*)
        __tdata_end = .;
    } > RAM AT> FLASH
    PROVIDE(__data_end__ = .);
    __etext = LOADADDR(.data);

    .tbss (NOLOAD) : {
        . = ALIGN(4);
        __bss_start__ = .;
        __tls_base = .;
        *(.tbss .tbss.* .gnu.linkonce.tb.*)
        *(.tcommon)
        __tls_end = .;
    } > RAM

    .bss (NOLOAD) : {
        . = ALIGN(4);
        __tbss_end = .;
        *(SORT_BY_ALIGNMENT(SORT_BY_NAME(.bss*)))
        *(COMMON)
        PROVIDE(__global_pointer$ = . + 2K);
        *(.sbss*)
        . = ALIGN(4);
        __bss_end__ = .;
    } > RAM

    .heap (NOLOAD) : {
        __end__ = .;
        end = __end__;
        KEEP(*(.heap*))
    } > RAM
    __HeapLimit = ORIGIN(RAM) + LENGTH(RAM);

    /* Secure has a single stack at the top of its RAM bank. core1 lives
     * in the NS image; this script does not touch SCRATCH_X / SCRATCH_Y. */
    .stack_dummy (NOLOAD) : { KEEP(*(.stack*)) } > RAM

    /* The SDK's crt0 unconditionally walks a data-copy table that
     * includes __scratch_x_* / __scratch_y_*. Provide zero-sized
     * sections so those symbols resolve and the copy loops are no-ops
     * -- Secure doesn't use the scratch banks at all (no core1, no
     * special .scratch_x / .scratch_y sections). */
    .scratch_x : {
        __scratch_x_start__ = .;
        . = ALIGN(4);
        __scratch_x_end__   = .;
    } > FLASH
    __scratch_x_source__ = LOADADDR(.scratch_x);

    .scratch_y : {
        __scratch_y_start__ = .;
        . = ALIGN(4);
        __scratch_y_end__   = .;
    } > FLASH
    __scratch_y_source__ = LOADADDR(.scratch_y);

    .flash_end : {
        KEEP(*(.embedded_end_block*))
        PROVIDE(__flash_binary_end = .);
    } > FLASH =0xaa

    __StackLimit = ORIGIN(RAM) + LENGTH(RAM);
    __StackTop   = ORIGIN(RAM) + LENGTH(RAM);
    __StackBottom = __StackTop - SIZEOF(.stack_dummy);
    PROVIDE(__stack = __StackTop);

    PROVIDE (__heap_start = __end__);
    PROVIDE (__heap_end   = __HeapLimit);
    PROVIDE( __tls_align        = MAX(ALIGNOF(.tdata), ALIGNOF(.tbss)) );
    PROVIDE( __tls_size_align   = (__tls_size + __tls_align - 1) & ~(__tls_align - 1));
    PROVIDE( __arm32_tls_tcb_offset = MAX(8, __tls_align) );
    PROVIDE (_end = __end__);
    PROVIDE (__llvm_libc_heap_limit = __HeapLimit);

    ASSERT(__StackLimit >= __HeapLimit, "Secure region RAM overflowed")
    ASSERT(__binary_info_header_end - __logical_binary_start <= 1024,
        "Binary info must be in first 1024 bytes of the binary")
    ASSERT(__embedded_block_end - __logical_binary_start <= 4096,
        "Embedded block must be in first 4096 bytes of the binary")
}
