"""Re-verify every decompiled function against the ROM.

One command to prove the whole set still matches after any change to the
interpreter or the decompilations.

usage: python verify_all.py [SCUS_972.05]
"""
import subprocess, sys

ELF = sys.argv[1] if len(sys.argv) > 1 else 'disc/SCUS_972.05'

# (rom function, decomp file, extra difftest args)
CASES = [
    ('po2',                      'decomp/po2.cpp',                            []),
    ('0x0031e1c0',               'decomp/CZWeapon_GetIDType.cpp', ['GetIDType']),
    ('quadW',                    'decomp/quadW.cpp',            ['quadW', '--float']),
    ('CPickup::GetPosW',         'decomp/methods/CPickup_GetPosW.cpp',    ['--obj=28']),
    ('CZWeapon::HasFireMode',    'decomp/methods/CZWeapon_HasFireMode.cpp', ['--obj=176']),
    ('CSaveModule::TestFlags',   'decomp/methods/CSaveModule_TestFlags.cpp', ['--obj=24']),
    ('CZFTSWeapon::IsM203Weapon',
     'decomp/methods/CZFTSWeapon_IsM203Weapon.cpp',                        ['--obj=460']),
    ('CSndInstance::IsFading',   'decomp/methods/CSndInstance_IsFading.cpp', ['--obj=40']),
    ('CZBodyAnim::SetTimeScale',
     'decomp/methods/CZBodyAnim_SetTimeScale.cpp',                          ['--obj=36']),
    ('CSequence::Tick',          'decomp/methods/CSequence_Tick.cpp',
     ['--obj=16', '--retf']),
    ('CFader::SetMinBrightness',
     'decomp/methods/CFader_SetMinBrightness.cpp',                         ['--obj=160']),
]


def main():
    ok = bad = 0
    for func, cpp, extra in CASES:
        r = subprocess.run([sys.executable, 'difftest.py', ELF, func, cpp] + extra,
                           capture_output=True, text=True)
        line = (r.stdout.strip().splitlines() or ['no output'])[-1].strip()
        status = 'PASS' if r.returncode == 0 else 'FAIL'
        ok += r.returncode == 0
        bad += r.returncode != 0
        print(f'  {status}  {func:28s} {line}')
    print(f'\n{ok} verified against the ROM, {bad} failing')
    return 1 if bad else 0


if __name__ == '__main__':
    sys.exit(main())
