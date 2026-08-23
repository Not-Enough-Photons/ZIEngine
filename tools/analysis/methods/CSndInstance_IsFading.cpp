// CSndInstance::IsFading  --  @ 0x002ef620 (40 bytes), sizeof=40
// True while the fade timer at +0x20 is still positive. The compare goes
// through ee_daz: a denormal timer reads as zero on hardware, not as a
// tiny positive number.
// --- Emotion Engine FPU semantics -------------------------------------
// The EE FPU is not IEEE754: it rounds toward zero (chop, not nearest),
// treats denormal inputs as zero, flushes denormal results to zero, and
// has no Inf -- overflow and divide-by-zero saturate at +/-FLT_MAX.
// Plain C++ float arithmetic differs by 1 ulp on ~half of all operations
// and treats denormals as nonzero, so a port that ignores this drifts.
// Operation ORDER matters too: chop is not associative.
#include <cmath>
#include <cstring>
#include <cstdint>
static const float EE_FMAX = 3.40282347e+38f;
static inline uint32_t ee_bits(float f) { uint32_t b; std::memcpy(&b, &f, 4); return b; }
static inline float ee_daz(float f) {                  // reading an operand
    uint32_t e = ee_bits(f) & 0x7f800000u;
    if (e == 0)           return std::copysignf(0.0f, f);
    if (e == 0x7f800000u) return std::copysignf(EE_FMAX, f);
    return f;
}
static inline float ee_chop(double d) {                // producing a result
    const double M = 3.40282346638528860e+38;
    if (d >  M) return  EE_FMAX;
    if (d < -M) return -EE_FMAX;
    float y = (float)d;
    if (std::fabs((double)y) > std::fabs(d)) y = std::nextafterf(y, 0.0f);
    if (!(ee_bits(y) & 0x7f800000u)) y = std::copysignf(0.0f, y);
    return y;
}
static inline float ee_add(float a, float b) { return ee_chop((double)ee_daz(a) + (double)ee_daz(b)); }
static inline float ee_sub(float a, float b) { return ee_chop((double)ee_daz(a) - (double)ee_daz(b)); }
static inline float ee_mul(float a, float b) { return ee_chop((double)ee_daz(a) * (double)ee_daz(b)); }
static inline float ee_div(float a, float b) {
    uint32_t bb = ee_bits(b);
    if ((bb & 0x7f800000u) == 0) {                     // zero OR denormal
        bool neg = ((ee_bits(a) ^ bb) & 0x80000000u) != 0;
        return neg ? -EE_FMAX : EE_FMAX;
    }
    return ee_chop((double)ee_daz(a) / (double)ee_daz(b));
}
// ----------------------------------------------------------------------
bool IsFading(const unsigned char* self)
{
    return ee_daz(*(const float*)(self + 0x20)) > 0.0f;
}
extern "C" unsigned test_entry(unsigned char* o, unsigned) { return IsFading(o); }
