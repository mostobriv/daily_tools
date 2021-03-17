//idk why there is no fucking presetted EFLAGS struct in ida

enum _EFLAGS {
    EFLAGS_CF       = 0x1,     // Carry flag
    EFLAGS_RSRVD1   = 0x2,     // Reserved, always 1 in EFLAGS
    EFLAGS_PF       = 0x4,     // Parity flag
    EFLAGS_RSRVD2   = 0x8,     // Reserved
    EFLAGS_AF       = 0x10,    // Adjust flag
    EFLAGS_RSRVD3   = 0x20,    // Reserved
    EFLAGS_ZF       = 0x40,    // Zero flag
    EFLAGS_SF       = 0x80,    // Sign flag
    EFLAGS_TF       = 0x100,   // Trap flag (Single step)
    EFLAGS_IF       = 0x200,   // Interrupt enable flag
    EFLAGS_DF       = 0x400,   // Direction flag
    EFLAGS_OF       = 0x800,   // Overflow flag
    EFLAGS_IOPL     = 0x3000,  // I/O privilege level (286+ only), always 1 on 8086 and 186
    EFLAGS_NT       = 0x4000,  // Nested task flag (286+ only), always 1 on 8086 and 186
    EFLAGS_RSRVD4   = 0x8000,  // Reserved, always 1 on 8086 and 186, always 0 on later models
    EFLAGS_RF       = 0x10000, // Resume flag (386+ only)
    EFLAGS_VM       = 0x20000, // Virtual 8086 mode flag (386+ only)
    EFLAGS_AC       = 0x40000, // Alignment check (486SX+ only)
    EFLAGS_VIF      = 0x80000, // Virtual interrupt flag (Pentium+)
    EFLAGS_VIP      = 0x100000,// Virtual interrupt pending (Pentium+)
    EFLAGS_ID       = 0x200000,// Able to use CPUID instruction (Pentium+)
};
