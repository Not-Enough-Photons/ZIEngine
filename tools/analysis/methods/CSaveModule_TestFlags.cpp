// CSaveModule::TestFlags  --  @ 0x001f2580 (44 bytes), sizeof(CSaveModule)=24
// mangled: TestFlags__11CSaveModuleCFi
// An exact match counts as set even when the stored mask is zero, so the
// equality test is not redundant with the bit test.
typedef unsigned int u32;
bool TestFlags(const unsigned char* self, int f)
{
    u32 mask = *(const u32*)(self + 0x10);
    if ((u32)f == mask) return true;
    return ((u32)f & mask) != 0;
}
extern "C" unsigned test_entry(unsigned char* o, unsigned a)
{ return TestFlags(o, (int)a); }
