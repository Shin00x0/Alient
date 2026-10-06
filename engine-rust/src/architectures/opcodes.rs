//! N04 opcode catalogue. Decoder mechanics live in the parent module.
pub fn is_fp_simd(arm: bool, mnemonic: &str) -> bool {
    if arm {
        return matches!(
            mnemonic,
            "fadd"
                | "fsub"
                | "fmul"
                | "fdiv"
                | "fsqrt"
                | "fmax"
                | "fmin"
                | "fmov"
                | "fcmp"
                | "fcvt"
                | "scvtf"
                | "ucvtf"
                | "fcvtzs"
                | "fcvtzu"
                | "dup"
                | "ins"
                | "movi"
        );
    }
    matches!(
        mnemonic,
        "addss"
            | "addsd"
            | "subss"
            | "subsd"
            | "mulss"
            | "mulsd"
            | "divss"
            | "divsd"
            | "sqrtss"
            | "sqrtsd"
            | "minss"
            | "minsd"
            | "maxss"
            | "maxsd"
            | "movss"
            | "movsd"
            | "ucomiss"
            | "ucomisd"
            | "comiss"
            | "comisd"
            | "cvtss2sd"
            | "cvtsd2ss"
            | "cvtsi2ss"
            | "cvtsi2sd"
            | "cvttss2si"
            | "cvttsd2si"
            | "addps"
            | "addpd"
            | "subps"
            | "subpd"
            | "mulps"
            | "mulpd"
            | "divps"
            | "divpd"
            | "sqrtps"
            | "sqrtpd"
            | "maxps"
            | "maxpd"
            | "minps"
            | "minpd"
            | "movaps"
            | "movups"
            | "movdqa"
            | "movdqu"
            | "pxor"
            | "por"
            | "pand"
            | "pandn"
            | "paddb"
            | "paddw"
            | "paddd"
            | "paddq"
            | "psubb"
            | "psubw"
            | "psubd"
            | "psubq"
            | "pshufd"
            | "shufps"
    )
}
pub fn is_special(arm: bool, mnemonic: &str) -> bool {
    if arm {
        matches!(mnemonic, "mrs" | "msr" | "dmb" | "dsb" | "isb")
    } else {
        matches!(
            mnemonic,
            "cpuid" | "rdtsc" | "rdtscp" | "xgetbv" | "rdrand" | "rdseed"
        )
    }
}
pub fn is_fp_compare(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "ucomiss" | "ucomisd" | "comiss" | "comisd" | "fcmp"
    )
}
pub fn may_trap(mnemonic: &str) -> bool {
    matches!(mnemonic, "divss" | "divsd" | "divps" | "divpd" | "fdiv")
}
