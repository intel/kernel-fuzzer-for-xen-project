#include <linux/module.h>
#include <linux/slab.h>

static char str[] = "deadbeef";

static inline void harness(void)
{
    unsigned int tmp;

    asm volatile ("cpuid"
                  : "=a" (tmp)
                  : "a" (0x13371337)
                  : "bx", "cx", "dx");
}

static int test(int *mem, int x, char c)
{
    if ( str[x] == c )
        return *mem;

    return 0;
}

static int my_init_module(void)
{
    int x;
    void *mem = kmalloc(4096, __GFP_DMA);

    printk(KERN_ALERT "Kernel Fuzzer Test Module str 0x%px mem 0x%px\n", str, mem);

    harness();

    x = test((int*)mem, 0, 'n');
    x += test((int*)mem, 1, 'o');

    harness();

    kfree(mem);

    printk(KERN_ALERT "Test: %i\n", x);

    return 0;
}

static void my_cleanup_module(void)
{
}

module_init(my_init_module);
module_exit(my_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Intel Corporation, Tamas K Lengyel");
MODULE_DESCRIPTION("Kernel Fuzzer test module");
