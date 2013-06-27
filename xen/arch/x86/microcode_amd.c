/*
 *  AMD CPU Microcode Update Driver for Linux
 *  Copyright (C) 2008 Advanced Micro Devices Inc.
 *
 *  Author: Peter Oruba <peter.oruba@amd.com>
 *
 *  Based on work by:
 *  Tigran Aivazian <tigran@aivazian.fsnet.co.uk>
 *
 *  This driver allows to upgrade microcode on AMD
 *  family 0x10 and 0x11 processors.
 *
 *  Licensed unter the terms of the GNU General Public
 *  License version 2. See file COPYING for details.
 */

#include <xen/config.h>
#include <xen/lib.h>
#include <xen/kernel.h>
#include <xen/init.h>
#include <xen/sched.h>
#include <xen/smp.h>
#include <xen/spinlock.h>

#include <asm/msr.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <asm/microcode.h>

#define UCODE_MAGIC                0x00414d44
#define UCODE_EQUIV_CPU_TABLE_TYPE 0x00000000
#define UCODE_UCODE_TYPE           0x00000001

/* serialize access to the physical write */
static DEFINE_SPINLOCK(microcode_update_lock);

struct equiv_cpu_entry *equiv_cpu_table;

static int collect_cpu_info(int cpu, struct cpu_signature *csig)
{
    struct cpuinfo_x86 *c = &cpu_data[cpu];

    memset(csig, 0, sizeof(*csig));

    if ( (c->x86_vendor != X86_VENDOR_AMD) || (c->x86 < 0x10) )
    {
        printk(KERN_ERR "microcode: CPU%d not a capable AMD processor\n",
               cpu);
        return -EINVAL;
    }

    rdmsrl(MSR_AMD_PATCHLEVEL, csig->rev);

    printk(KERN_DEBUG "microcode: collect_cpu_info: patch_id=0x%x\n",
           csig->rev);

    return 0;
}

static int microcode_fits(void *mc, int cpu)
{
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    struct microcode_header_amd *mc_header = mc;
    unsigned int current_cpu_id;
    unsigned int equiv_cpu_id = 0x0;
    unsigned int i;

    /* We should bind the task to the CPU */
    BUG_ON(cpu != raw_smp_processor_id());

    current_cpu_id = cpuid_eax(0x00000001);

    for ( i = 0; equiv_cpu_table[i].installed_cpu != 0; i++ )
    {
        if ( current_cpu_id == equiv_cpu_table[i].installed_cpu )
        {
            equiv_cpu_id = equiv_cpu_table[i].equiv_cpu & 0xffff;
            break;
        }
    }

    if ( !equiv_cpu_id )
        return 0;

    if ( (mc_header->processor_rev_id) != equiv_cpu_id )
    {
        printk(KERN_DEBUG "microcode: CPU%d patch does not match "
               "(patch is %x, cpu base id is %x) \n",
               cpu, mc_header->processor_rev_id, equiv_cpu_id);
        return -EINVAL;
    }

    if ( mc_header->patch_id <= uci->cpu_sig.rev )
        return 0;

    printk(KERN_DEBUG "microcode: CPU%d found a matching microcode "
           "update with version 0x%x (current=0x%x)\n",
           cpu, mc_header->patch_id, uci->cpu_sig.rev);

    return 1;
}

static int apply_microcode(int cpu)
{
    unsigned long flags;
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    uint32_t rev;
    struct microcode_amd *mc_amd = uci->mc.mc_amd;

    /* We should bind the task to the CPU */
    BUG_ON(raw_smp_processor_id() != cpu);

    if ( mc_amd == NULL )
        return -EINVAL;

    spin_lock_irqsave(&microcode_update_lock, flags);

    wrmsrl(MSR_AMD_PATCHLOADER, (unsigned long)&mc_amd->hdr.data_code);

    /* get patch id after patching */
    rdmsrl(MSR_AMD_PATCHLEVEL, rev);

    spin_unlock_irqrestore(&microcode_update_lock, flags);

    /* check current patch id and patch's id for match */
    if ( rev != mc_amd->hdr.patch_id )
    {
        printk(KERN_ERR "microcode: CPU%d update from revision "
               "0x%x to 0x%x failed\n", cpu,
               mc_amd->hdr.patch_id, rev);
        return -EIO;
    }

    printk(KERN_INFO "microcode: CPU%d updated from revision %#x to %#x\n",
           cpu, uci->cpu_sig.rev, mc_amd->hdr.patch_id);

    uci->cpu_sig.rev = rev;

    return 0;
}

static int get_next_ucode_from_buffer_amd(
    void **mc,
    size_t *mc_size,
    const void *buf,
    size_t size,
    unsigned long *offset)
{
    struct microcode_header_amd *mc_header;
    size_t total_size;
    const uint8_t *bufp = buf;
    unsigned long off;

    off = *offset;

    /* No more data */
    if ( off >= size )
        return 1;

    if ( bufp[off] != UCODE_UCODE_TYPE )
    {
        printk(KERN_ERR "microcode: error! "
               "Wrong microcode payload type field\n");
        return -EINVAL;
    }

    mc_header = (struct microcode_header_amd *)(&bufp[off+8]);

    total_size = (unsigned long) (bufp[off+4] + (bufp[off+5] << 8));

    printk(KERN_DEBUG "microcode: size %lu, total_size %lu, offset %ld\n",
           (unsigned long)size, total_size, off);

    if ( (off + total_size) > size )
    {
        printk(KERN_ERR "microcode: error! Bad data in microcode data file\n");
        return -EINVAL;
    }

    if ( *mc_size < total_size )
    {
        xfree(*mc);
        *mc = xmalloc_bytes(total_size);
        if ( !*mc )
            return -ENOMEM;
        *mc_size = total_size;
    }
    else if ( *mc_size > total_size )
        memset(*mc + total_size, 0, *mc_size - total_size);
    memcpy(*mc, mc_header, total_size);

    *offset = off + total_size + 8;

    return 0;
}

static int install_equiv_cpu_table(const void *buf, uint32_t size,
                                   unsigned long *offset)
{
    const uint32_t *buf_pos = buf;
    unsigned long off;

    off = *offset;
    *offset = 0;

    /* No more data */
    if ( off >= size )
        return -EINVAL;

    if ( buf_pos[1] != UCODE_EQUIV_CPU_TABLE_TYPE )
    {
        printk(KERN_ERR "microcode: error! "
               "Wrong microcode equivalent cpu table type field\n");
        return -EINVAL;
    }

    if ( size == 0 )
    {
        printk(KERN_ERR "microcode: error! "
               "Wrong microcode equivalnet cpu table length\n");
        return -EINVAL;
    }

    equiv_cpu_table = xmalloc_bytes(size);
    if ( equiv_cpu_table == NULL )
    {
        printk(KERN_ERR "microcode: error, can't allocate "
               "memory for equiv CPU table\n");
        return -ENOMEM;
    }

    memset(equiv_cpu_table, 0, size);
    memcpy(equiv_cpu_table, (const void *)&buf_pos[3], size);

    *offset = size + 12;	/* add header length */

    return 0;
}

static int cpu_request_microcode(int cpu, const void *buf, size_t size)
{
    const uint32_t *buf_pos;
    unsigned long offset = 0;
    int error;
    struct ucode_cpu_info *uci = &per_cpu(ucode_cpu_info, cpu);
    void *mc;
    size_t mc_size;

    /* We should bind the task to the CPU */
    BUG_ON(cpu != raw_smp_processor_id());

    buf_pos = (const uint32_t *)buf;

    if ( buf_pos[0] != UCODE_MAGIC )
    {
        printk(KERN_ERR "microcode: error! Wrong "
               "microcode patch file magic\n");
        return -EINVAL;
    }

    error = install_equiv_cpu_table(buf, (uint32_t)(buf_pos[2]), &offset);
    if ( error )
    {
        printk(KERN_ERR "microcode: installing equivalent cpu table failed\n");
        return -EINVAL;
    }

    /* Size of 1st microcode patch in bytes */
    mc_size = buf_pos[offset / sizeof(*buf_pos) + 1];
    mc = xmalloc_bytes(mc_size);
    if ( mc == NULL )
    {
        printk(KERN_ERR "microcode: error! "
               "Can not allocate memory for microcode patch\n");
        error = -ENOMEM;
        goto out;
    }

    /* implicitely validates uci->mc.mc_valid */
    uci->mc.mc_amd = mc;

    /*
     * It's possible the data file has multiple matching ucode,
     * lets keep searching till the latest version
     */
    while ( (error = get_next_ucode_from_buffer_amd(&mc, &mc_size, buf, size,
                                                    &offset)) == 0 )
    {
        uci->mc.mc_amd = mc;

        error = microcode_fits(mc, cpu);
        if (error <= 0)
            continue;

        error = apply_microcode(cpu);
        if (error == 0)
        {
            error = 1;
            break;
        }
    }

    /* On success keep the microcode patch for
     * re-apply on resume.
     */
    if ( error <= 0 )
    {
        xfree(mc);
        mc = NULL;
    }
    else
        error = 0;
    uci->mc.mc_amd = mc;

out:
    xfree(equiv_cpu_table);
    equiv_cpu_table = NULL;

    return error;
}

static int microcode_resume_match(int cpu, struct cpu_signature *nsig)
{
    return 0;
}

static const struct microcode_ops microcode_amd_ops = {
    .microcode_resume_match           = microcode_resume_match,
    .cpu_request_microcode            = cpu_request_microcode,
    .collect_cpu_info                 = collect_cpu_info,
    .apply_microcode                  = apply_microcode,
};

static __init int microcode_init_amd(void)
{
    if ( boot_cpu_data.x86_vendor == X86_VENDOR_AMD )
        microcode_ops = &microcode_amd_ops;
    return 0;
}
__initcall(microcode_init_amd);
