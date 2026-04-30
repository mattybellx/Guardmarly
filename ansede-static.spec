# -*- mode: python ; coding: utf-8 -*-
import os


a = Analysis(
    ['src\\ansede_static\\cli.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ansede-static',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    # Set ANSEDE_TARGET_ARCH to "x86_64" or "arm64" in CI release jobs.
    target_arch=os.environ.get('ANSEDE_TARGET_ARCH') or None,
    codesign_identity=None,
    entitlements_file=None,
)
