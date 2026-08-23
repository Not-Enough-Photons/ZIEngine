// CZFTSWeapon::IsM203Weapon  --  @ 0x003158c0 (40 bytes), sizeof=460
// mangled: IsM203Weapon__11CZFTSWeaponFv
// Two weapon-type ids carry the M203 launcher.
bool IsM203Weapon(const unsigned char* self)
{
    unsigned char t = self[0x60];
    return t == 0x34 || t == 0x3d;
}
extern "C" unsigned test_entry(unsigned char* o, unsigned) { return IsM203Weapon(o); }
