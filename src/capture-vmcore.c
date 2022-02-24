/*
 * SPDX-License-Identifier: MIT
 *
 * This tool fetches Linux vmcore from VMs that are paused at the beginning of a
 * kernel crash (e.g oops_begin).
 */
#include <elf.h>
#include <getopt.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>

#include "vmi.h"
#include "signal.h"


addr_t target_pagetable;
addr_t start_rip;
os_t os;
int interrupted, loopmode;
page_mode_t pm;
vmi_instance_t vmi;

vmi_event_t interrupt_event;
addr_t machine_kexec;
uint8_t old_machine_kexec_insn;

static void options(void)
{
    printf("Options:\n");
    printf("\t--domain <domain name>\n");
    printf("\t--domid <domain id>\n");
    printf("\t--json <path to kernel debug json>\n");
    printf("\t--out <path for output vmcore file>\n");
    printf("\t--panic-on-warn\n");
}

static event_response_t int3_cb(vmi_instance_t vmi, vmi_event_t *event)
{
    event->interrupt_event.reinject = 1;
    if (event->interrupt_event.gla == machine_kexec)
    {
        vmi_write_8_va(vmi, machine_kexec, 0, &old_machine_kexec_insn);
        vmi_pause_vm(vmi);
        interrupted = 1;
    }
    return 0;
}

static bool apply_panic_on_warn(vmi_instance_t vmi)
{
    uint32_t pow = 1;
    uint64_t kasan_flags = 0;
    if ( VMI_FAILURE == vmi_write_32_ksym(vmi, "panic_on_warn", &pow) )
    {
        fprintf(stderr, "Failed to enable panic_on_warn\n");
        return false;
    }
    printf("Force enabled panic_on_warn\n");

    /* Unset KASAN_BIT_REPORTED and KASAN_BIT_MULTI_SHOT so that panic_on_warn is not ignored. */
    if ( VMI_FAILURE == vmi_read_64_ksym(vmi, "kasan_flags", &kasan_flags) )
    {
        fprintf(stderr, "Unable to locate kasan_flags. Assuming KASAN is disabled\n");
    }
    else
    {
        kasan_flags &= ~0x3;
        if ( VMI_FAILURE == vmi_write_64_ksym(vmi, "kasan_flags", &kasan_flags) )
        {
            fprintf(stderr, "Failed to write to kasan_flags\n");
            return false;
        }
        printf("Force disabled KASAN multishot and reported bits\n");
    }

    return true;
}

static bool resume_and_break_at_kexec(vmi_instance_t vmi)
{
    uint8_t cc = 0xcc;
    SETUP_INTERRUPT_EVENT(&interrupt_event, int3_cb);
    if ( (VMI_FAILURE == vmi_read_8_va(vmi, machine_kexec, 0, &old_machine_kexec_insn)) ||
        (VMI_FAILURE == vmi_write_8_va(vmi, machine_kexec, 0, &cc)) ||
        (VMI_FAILURE == vmi_register_event(vmi, &interrupt_event)) )
    {
        fprintf(stderr, "Failed to set a breakpoint at kexec\n");
        return false;
    }
    loop(vmi);
    return true;
}

static bool append_mem_to_file(vmi_instance_t vmi, addr_t pa, size_t size, FILE *out)
{
    static char buf[4096];
    size_t total_read = 0;
    while ( total_read < size )
    {
        size_t to_read, read;
        to_read = ( sizeof(buf) < size - total_read ) ? sizeof(buf) : size - total_read;
        if ( (VMI_FAILURE == vmi_read_pa(vmi, pa + total_read, to_read, buf, &read)) ||
            (to_read != read) )
        {
            fprintf(stderr, "Failed to read %zu bytes at 0x%lx\n", size, pa);
            return false;
        }
        fwrite(buf, to_read, 1, out);
        total_read += read;
    }
    return true;
}

static bool dump_vmcore(vmi_instance_t vmi, addr_t elf_load_addr, addr_t elf_headers_sz, FILE *out)
{
    char elfcorehdr[elf_headers_sz];
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    int seg;
    size_t read = 0, total_notes_memsz = 0;

    if ( (VMI_FAILURE == vmi_read_pa(vmi, elf_load_addr, elf_headers_sz, elfcorehdr, &read)) ||
        (elf_headers_sz != read) )
    {
        fprintf(stderr, "Failed to read ELF header at 0x%lx\n", elf_load_addr);
        return false;
    }

    /*
     * Skip the header for now. It will be modified a bit as we go.
     */
    fseek(out, elf_headers_sz, SEEK_SET);

    ehdr = (Elf64_Ehdr*) elfcorehdr;
    if (ehdr->e_machine != EM_X86_64)
    {
        fprintf(stderr, "Unexpected ELF machine type: %d\n", ehdr->e_machine);
        return false;
    }
    phdr = (Elf64_Phdr*) &elfcorehdr[ehdr->e_phoff];

    /*
    * First squash all the PT_NOTE segments at the beginning of the list.
    */
    if ( ehdr->e_phnum > 0 && (PT_NOTE != phdr[0].p_type) )
    {
        fprintf(stderr, "Expected first program segment to be of type PT_NOTE\n");
        return false;
    }

    phdr[0].p_offset = ftell(out);
    for ( seg = 0; seg < ehdr->e_phnum && phdr[seg].p_type == PT_NOTE; ++seg )
    {
        Elf64_Nhdr nhdr;
        size_t memsz = 0;

        if ( VMI_FAILURE == vmi_read_pa(vmi, phdr[seg].p_paddr, sizeof(nhdr), &nhdr, &read) )
        {
            fprintf(stderr, "Failed to read %zu bytes at 0x%lx\n", sizeof(nhdr), phdr[seg].p_paddr);
            return false;
        }
        fwrite(&nhdr, sizeof(nhdr), 1, out);

        memsz = sizeof(nhdr) + ((nhdr.n_namesz + 3) & ~3) + ((nhdr.n_descsz + 3) & ~3);
        if ( !append_mem_to_file(vmi, phdr[seg].p_paddr + sizeof(nhdr), memsz - sizeof(nhdr), out) )
            return false;
        total_notes_memsz += memsz;
    }
    phdr[0].p_memsz = phdr[0].p_filesz = total_notes_memsz;
    memmove(&phdr[1], &phdr[seg], (ehdr->e_phnum - seg) * sizeof(phdr[0]));
    ehdr->e_phnum -= (seg - 1);

    /*
     * Next, copy all of the subsequent segments.
     */
    for ( seg = 1; seg < ehdr->e_phnum; ++seg )
    {
        phdr[seg].p_offset = ftell(out);
        if ( phdr[seg].p_type == PT_NOTE )
        {
            fprintf(stderr, "Encountered a PT_NOTE segment in an unexpected location\n");
            return false;
        }
        if ( !append_mem_to_file(vmi, phdr[seg].p_paddr, phdr[seg].p_memsz, out) )
            return false;
    }

    /*
     * Finally, write out the header.
     */
    fseek(out, 0, SEEK_SET);
    fwrite(elfcorehdr, elf_headers_sz, 1, out);
    return true;
}

int main(int argc, char** argv)
{
    vmi_instance_t vmi;
    addr_t kexec_crash_image = 0, elf_load_addr = 0;
    addr_t kimage_arch_offset = 0, elf_load_addr_offset = 0, elf_headers_sz_offset = 0;
    size_t elf_headers_sz = 0;
    FILE *out = NULL;
    int c, long_index = 0;
    const struct option long_opts[] =
    {
        {"domain", required_argument, NULL, 'd'},
        {"domid", required_argument, NULL, 'i'},
        {"json", required_argument, NULL, 'j'},
        {"out", required_argument, NULL, 'o'},
        {"panic-on-warn", no_argument, NULL, 'p'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0}
    };
    const char* opts = "d:i:j:ph";
    uint32_t domid = 0;
    char *domain = NULL;
    char *json = NULL;
    char *outfile = NULL;
    bool force_pow = false;

    while ((c = getopt_long (argc, argv, opts, long_opts, &long_index)) != -1)
    {
        switch(c)
        {
            case 'd':
                domain = optarg;
                break;
            case 'i':
                domid = strtoul(optarg, NULL, 0);
                break;
            case 'j':
                json = optarg;
                break;
            case 'o':
                outfile = optarg;
                break;
            case 'p':
                force_pow = true;
                break;
            case 'h': /* fall-through */
            default:
                options();
                return -1;
        };
    }

    if ( (!domid && !domain) || !json || !outfile )
    {
        options();
        return -1;
    }

    setup_handlers();

    if ( !setup_vmi(&vmi, domain, domid, NULL, NULL, true, false) )
    {
        printf("Failed to enable LibVMI\n");
        return -1;
    }

    if ( vmi_get_num_vcpus(vmi) > 1 )
    {
        printf("More than 1 vCPUs are not supported\n");
        goto done;
    }

    if ( VMI_OS_LINUX != vmi_init_os(vmi, VMI_CONFIG_JSON_PATH, json, NULL) )
    {
        printf("Failed to initialize VMI for Linux\n");
        goto done;
    }

    if ( (VMI_FAILURE == vmi_translate_ksym2v(vmi, "machine_kexec", &machine_kexec)) )
    {
        fprintf(stderr, "Cannot find the machine_kexec function\n");
        goto done;
    }

    if ( (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "kimage", "arch", &kimage_arch_offset)) ||
        (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "kimage_arch", "elf_load_addr", &elf_load_addr_offset)) ||
        (VMI_FAILURE == vmi_get_kernel_struct_offset(vmi, "kimage_arch", "elf_headers_sz", &elf_headers_sz_offset)) )
    {
        fprintf(stderr, "Cannot find device kimage and/or elf_headers offsets\n");
        goto done;
    }
    if ( (VMI_FAILURE == vmi_read_addr_ksym(vmi, "kexec_crash_image", &kexec_crash_image)) ||
        (0 == kexec_crash_image) ||
        VMI_FAILURE == vmi_read_addr_va(vmi, kexec_crash_image + kimage_arch_offset + elf_load_addr_offset, 0, &elf_load_addr) ||
        (0 == elf_load_addr) ||
        VMI_FAILURE == vmi_read_addr_va(vmi, kexec_crash_image + kimage_arch_offset + elf_headers_sz_offset, 0, &elf_headers_sz) ||
        (0 == elf_headers_sz) )
    {
        fprintf(stderr, "Either kexec_crash_image or elf_load_addr was not found, or was found to be NULL\n");
        fprintf(stderr, "Hint: Arm a kdump kernel with 'kexec -p' before running kfx --setup\n");
        goto done;

    }
    printf("Found vmcore ELF header at PA 0x%lx\n", elf_load_addr);

    if ( force_pow && !apply_panic_on_warn(vmi) )
        goto done;

    printf("Resuming VM until kdump kexec to populate/update all segments\n");
    if ( !resume_and_break_at_kexec(vmi) )
        goto done;
    umask(S_IWGRP|S_IWOTH);
    out = fopen(outfile, "w+");
    printf("Dumping vmcore. This may take some time...\n");
    if ( !dump_vmcore(vmi, elf_load_addr, elf_headers_sz, out) )
        goto done;
    printf("Successfully dumped vmcore to %s\n", outfile);

done:
    if ( out )
        fclose(out);
    vmi_destroy(vmi);

    return 0;
}
