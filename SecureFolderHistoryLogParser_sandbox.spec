# -*- mode: python ; coding: utf-8 -*-
# Sandbox build of the fixed parser. Mirrors the released spec but targets the
# sandbox script and emits a distinctly named exe so it cannot be confused with
# the shipped v1.0-RC1 binary.

datas = []
binaries = []
hiddenimports = ['PySide6.QtCore', 'PySide6.QtGui', 'PySide6.QtWidgets']
excludes = [
    'PySide6.Qt3DAnimation',
    'PySide6.Qt3DCore',
    'PySide6.Qt3DExtras',
    'PySide6.Qt3DInput',
    'PySide6.Qt3DLogic',
    'PySide6.Qt3DRender',
    'PySide6.QtAxContainer',
    'PySide6.QtBluetooth',
    'PySide6.QtCharts',
    'PySide6.QtDataVisualization',
    'PySide6.QtDesigner',
    'PySide6.QtGraphs',
    'PySide6.QtGraphsWidgets',
    'PySide6.QtHelp',
    'PySide6.QtHttpServer',
    'PySide6.QtLocation',
    'PySide6.QtMultimedia',
    'PySide6.QtMultimediaWidgets',
    'PySide6.QtNetworkAuth',
    'PySide6.QtNfc',
    'PySide6.QtPdf',
    'PySide6.QtPdfWidgets',
    'PySide6.QtPositioning',
    'PySide6.QtQml',
    'PySide6.QtQuick',
    'PySide6.QtQuick3D',
    'PySide6.QtQuickControls2',
    'PySide6.QtQuickTest',
    'PySide6.QtQuickWidgets',
    'PySide6.QtRemoteObjects',
    'PySide6.QtScxml',
    'PySide6.QtSensors',
    'PySide6.QtSerialBus',
    'PySide6.QtSerialPort',
    'PySide6.QtSpatialAudio',
    'PySide6.QtSql',
    'PySide6.QtStateMachine',
    'PySide6.QtSvg',
    'PySide6.QtSvgWidgets',
    'PySide6.QtTest',
    'PySide6.QtTextToSpeech',
    'PySide6.QtUiTools',
    'PySide6.QtWebChannel',
    'PySide6.QtWebEngineCore',
    'PySide6.QtWebEngineQuick',
    'PySide6.QtWebEngineWidgets',
    'PySide6.QtWebSockets',
    'PySide6.QtWebView',
    'PySide6.QtXml',
    'PySide6.scripts',
]


a = Analysis(
    ['samsung_secure_folder_historylog_parser.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    noarchive=False,
    optimize=0,
)

def keep_entry(entry):
    name = entry[0].replace('\\', '/')
    excluded_exact = {
        'PySide6/Qt6Pdf.dll',
        'PySide6/Qt6Qml.dll',
        'PySide6/Qt6QmlModels.dll',
        'PySide6/Qt6Quick.dll',
        'PySide6/Qt6VirtualKeyboard.dll',
        'PySide6/Qt6OpenGL.dll',
        'PySide6/Qt6Svg.dll',
        'PySide6/QtPdf.pyd',
        'PySide6/QtQml.pyd',
        'PySide6/QtQuick.pyd',
        'PySide6/QtVirtualKeyboard.pyd',
        'PySide6/QtOpenGL.pyd',
        'PySide6/QtSvg.pyd',
        'PySide6/opengl32sw.dll',
    }
    excluded_prefixes = (
        'PySide6/translations/',
        'PySide6/plugins/imageformats/',
        'PySide6/plugins/iconengines/',
        'PySide6/plugins/platforms/qdirect2d',
        'PySide6/plugins/platforms/qminimal',
        'PySide6/plugins/platforms/qoffscreen',
        'PySide6/plugins/platforms/qwebgl',
        'PySide6/qml/',
    )
    return name not in excluded_exact and not any(
        name.startswith(prefix) for prefix in excluded_prefixes
    )


a.binaries = [entry for entry in a.binaries if keep_entry(entry)]
a.datas = [entry for entry in a.datas if keep_entry(entry)]
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SecureFolderHistoryLogParser_sandbox',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
