// CPickup::GetPosW  --  SCUS_972.05 @ 0x0024c400 (32 bytes), sizeof(CPickup)=28
// mangled: GetPosW__7CPickupCFv
// Returns &node->pos (node field +0x30), or null when the node is unset.
// Pointer values are kept as u32 so the test can compare across address spaces.
typedef unsigned int u32;
u32 GetPosW(const unsigned char* self)
{
    u32 node = *(const u32*)(self + 0x00);
    return node ? node + 0x30 : 0;
}
extern "C" unsigned test_entry(unsigned char* o, unsigned) { return GetPosW(o); }
