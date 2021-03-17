//idk why there is no fucking presetted EFLAGS struct in ida

enum _EFLAGS {
    CF       = 0x1,     // Carry flag
    RSRVD1   = 0x2,     // Reserved, always 1 in EFLAGS
    PF       = 0x4,     // Parity flag
    RSRVD2   = 0x8,     // Reserved
    AF       = 0x10,    // Adjust flag
    RSRVD3   = 0x20,    // Reserved
    ZF       = 0x40,    // Zero flag
    SF       = 0x80,    // Sign flag
    TF       = 0x100,   // Trap flag (Single step)
    IF       = 0x200,   // Interrupt enable flag
    DF       = 0x400,   // Direction flag
    OF       = 0x800,   // Overflow flag
    IOPL     = 0x3000,  // I/O privilege level (286+ only), always 1 on 8086 and 186
    NT       = 0x4000,  // Nested task flag (286+ only), always 1 on 8086 and 186
    RSRVD4   = 0x8000,  // Reserved, always 1 on 8086 and 186, always 0 on later models
    RF       = 0x10000, // Resume flag (386+ only)
    VM       = 0x20000, // Virtual 8086 mode flag (386+ only)
    AC       = 0x40000, // Alignment check (486SX+ only)
    VIF      = 0x80000, // Virtual interrupt flag (Pentium+)
    VIP      = 0x100000,// Virtual interrupt pending (Pentium+)
    ID       = 0x200000,// Able to use CPUID instruction (Pentium+)
};
