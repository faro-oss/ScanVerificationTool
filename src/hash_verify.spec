# -*- mode: python -*-
import PyQt5
import ntpath
import certifi

with open('src/version.txt') as f:
    version  = f.readline().strip()

block_cipher = None


my_datas = [('../images', 'images'),
           ('../keys', 'keys'),
           ('../licenses', 'licenses'),
           ('../manual/*.pdf', 'manual')]

# Collect Certificates
from PyInstaller.utils.hooks import exec_statement
cert_datas = certifi.where()
if cert_datas is not None:
    my_datas.append((str(cert_datas), 'cert'))

a = Analysis(
    ['hash_verify.py'],
    pathex=['src', os.path.join(ntpath.dirname(PyQt5.__file__), 'Qt', 'bin')],
    binaries=[],
    datas=my_datas,
    hiddenimports=[],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False)

pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='hash_verify',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    console=False,
    icon='../images/verify.ico',
    version='VSVersionInfo.txt')

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    name='hash_verify')

app = BUNDLE(coll,
    name='FARO Scan Verification Tool.app',
    icon='../images/verify.icns',
    bundle_identifier='com.faro.scan_verification_tool',
    info_plist={
        'NSPrincipleClass': 'NSApplication',
        'NSAppleScriptEnabled': False,
        'NSHighResolutionCapable': 'True',
        'CFBundleShortVersionString': version
        })
