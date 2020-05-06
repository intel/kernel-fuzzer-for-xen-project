#include <linux/module.h>

static char test1[] = "deadbeef";
static char test2[] = "nottbeef";

static inline void harness(void)
{
    asm (
        "push %rax\n\t"
        "push %rbx\n\t"
        "push %rcx\n\t"
        "push %rdx\n\t"
        "movq $0x13371337,%rax\n\t"
        "cpuid\n\t"
        "pop %rdx\n\t"
        "pop %rcx\n\t"
        "pop %rbx\n\t"
        "pop %rax\n\t"
    );
}

static int path1(int x)
{
    return ++x;
}
static int path2(int x)
{
    return x+12;
}
static int path3(int x)
{
    return x*12;
}
static int path4(int x)
{
    return --x;
}

static int *test(int x)
{
    int *y = NULL;

    switch(x % 4) {
    case 0:
        x = path1(x);
        break;
    case 1:
        x = path2(x);
        break;
    case 2:
        x = path3(x);
        break;
    case 3:
        x = path4(x);
        break;
    };

    if ( !memcmp(test1, test2, 8) )
        *y = x; // NULL-deref oops

    return y;
}

static int my_init_module(void)
{
    int *x = NULL;

    printk(KERN_ALERT "Kernel Fuzzer Test Module Test1 %px %s Test2 %px %s\n", test1, test1, test2, test2);

    harness();

    x = test((int)test1[0]);

    harness();

    printk(KERN_ALERT "Test: %px\n", x);

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
