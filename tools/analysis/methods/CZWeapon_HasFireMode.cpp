// CZWeapon::HasFireMode  --  @ 0x0031eee0 (36 bytes), sizeof(CZWeapon)=176
// mangled: HasFireMode__8CZWeaponCFi
// Modes 0..4 index a byte table at +0xa8; anything >= 5 is reported present.
// The ROM compares signed, so a negative mode indexes before the table --
// reproduced rather than corrected.
int HasFireMode(const unsigned char* self, int mode)
{
    if (mode >= 5) return 1;
    return self[0xa8 + mode];
}
extern "C" unsigned test_entry(unsigned char* o, unsigned a)
{ return (unsigned)HasFireMode(o, (int)a); }
