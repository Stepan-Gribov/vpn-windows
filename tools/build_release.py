#!/usr/bin/env python3
"""Cross-build using existing Go and the existing Windows Framework compiler.

No toolchain installation or dependency download. Source archives include the
exact patched Xray/AWG sources; runtime states and test credentials are excluded.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
PROJECT = json.loads((ROOT / 'project.json').read_text())
NAME = f"TnDtun-{PROJECT['version']}-{PROJECT['target']}"
ENV = dict(os.environ, GOOS='windows', GOARCH='amd64', CGO_ENABLED='0', GOPROXY='off', GOSUMDB='off', GOTOOLCHAIN='local')
ENGINE = ROOT / 'native/CombinedXray'


def run(args, **kw):
    return subprocess.run(args, check=True, env=ENV, **kw)


def ps(host, script, **kw):
    encoded = base64.b64encode(script.encode('utf-16le')).decode()
    return run(['ssh', host, 'powershell -NoProfile -NonInteractive -EncodedCommand '+encoded], **kw)


def build_metadata():
    if not re.fullmatch(r'\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?', PROJECT['version']):
        raise ValueError('Invalid version in project.json')
    parts = PROJECT['fileVersion'].split('.')
    if len(parts) != 4 or any(not p.isdecimal() or int(p) > 65534 for p in parts):
        raise ValueError('Invalid fileVersion in project.json')
    now = dt.datetime.now(dt.timezone.utc)
    commit = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], capture_output=True, text=True)
    revision = commit.stdout.strip() if commit.returncode == 0 else 'unknown'
    dirty = None
    if revision != 'unknown':
        diff = subprocess.run(['git', '-C', str(ROOT), 'diff', '--quiet', 'HEAD', '--'], env=ENV)
        if diff.returncode > 1:
            raise RuntimeError('Cannot compare source revision')
        dirty = diff.returncode != 0 or bool(run(['git', '-C', str(ROOT), 'ls-files', '--others', '--exclude-standard'], capture_output=True, text=True).stdout)
    build_id = now.strftime('%Y%m%dT%H%M%S') + f'{now.microsecond // 1000:03d}Z-' + (revision[:8] if revision != 'unknown' else 'source') + ('-dirty' if dirty else '')
    return dict(schema=1, product=PROJECT['name'], version=PROJECT['version'], fileVersion=PROJECT['fileVersion'],
                buildId=build_id, builtAtUtc=now.isoformat(), sourceCommit=revision, sourceDirty=dirty,
                target=PROJECT['target'], framework=PROJECT['framework'], transports=PROJECT['transports'],
                goVersion=run(['go', 'version'], capture_output=True, text=True).stdout.strip())


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def archive(folder, output, prefix):
    with zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(folder.rglob('*')):
            if p.is_file():
                z.write(p, str(Path(prefix) / p.relative_to(folder)))


def licenses():
    dest = ROOT / 'licenses'
    if dest.exists(): shutil.rmtree(dest)
    dest.mkdir(exist_ok=True)
    proc = run(['go', '-C', str(ENGINE), 'list', '-m', '-json', 'all'], capture_output=True, text=True)
    used = set(run(['go','-C',str(ENGINE),'list','-deps','-f','{{if .Module}}{{.Module.Path}}{{end}}','./cmd/tndtun-engine'],capture_output=True,text=True).stdout.splitlines())
    decoder, pos, mods = json.JSONDecoder(), 0, []
    while pos < len(proc.stdout):
        while pos < len(proc.stdout) and proc.stdout[pos].isspace(): pos += 1
        if pos == len(proc.stdout): break
        value, pos = decoder.raw_decode(proc.stdout, pos)
        if value.get('Main') or value['Path'] not in used: continue
        directory = value.get('Replace', value).get('Dir')
        name = value['Path'].replace('/', '_').replace(':', '_')
        copied = []
        if directory:
            for p in sorted(Path(directory).iterdir()):
                if p.is_file() and p.name.upper().startswith(('LICENSE','COPYING','NOTICE','PATENTS','AUTHORS')):
                    target = dest / name / p.name
                    target.parent.mkdir(exist_ok=True)
                    shutil.copyfile(p, target)
                    copied.append(str(target.relative_to(ROOT)))
        mods.append({'module': value['Path'], 'version': value.get('Version'), 'replacement': value.get('Replace', {}).get('Path'), 'notices': copied})
    goroot = Path(run(['go','env','GOROOT'],capture_output=True,text=True).stdout.strip())
    (dest/'Go').mkdir(exist_ok=True)
    go_license = next((p for p in (goroot/'LICENSE',goroot.parent/'LICENSE') if p.is_file()),None)
    if go_license is None: raise RuntimeError('Go license is missing from this toolchain distribution')
    shutil.copyfile(go_license,dest/'Go/LICENSE')
    for mod in mods:
        if mod['notices']: continue
        directory=dest/mod['module'].replace('/','_')
        directory.mkdir(exist_ok=True)
        if mod['module']=='github.com/KindlyVPN/foundation/transports':
            shutil.copyfile(ROOT/'LICENSE',directory/'LICENSE')
            shutil.copyfile(ROOT/'native/Recovery/THIRD_PARTY.md',directory/'THIRD_PARTY.md')
        elif mod['module']=='github.com/bogdanfinn/fhttp':
            cache=Path(run(['go','env','GOMODCACHE'],capture_output=True,text=True).stdout.strip())
            upstream=cache/(mod['module']+'@'+mod['version'])
            shutil.copyfile(go_license,directory/'GO-BSD-LICENSE')
            shutil.copyfile(upstream/'README.md',directory/'UPSTREAM-README.md')
            (directory/'NOTICE.txt').write_text('fhttp v0.6.8 is a net/http fork. Its Go source headers retain The Go Authors copyright and reference the Go BSD license, reproduced here. The module archive does not include a top-level LICENSE file. Upstream credits are retained in UPSTREAM-README.md. Source: https://github.com/bogdanfinn/fhttp/tree/v0.6.8\n')
        mod['notices']=[str(p.relative_to(ROOT)) for p in sorted(directory.iterdir()) if p.is_file()]
    (dest / 'DEPENDENCIES.json').write_text(json.dumps(mods, indent=2)+'\n')
    for p in (goroot/'src/vendor').rglob('*'):
        if p.is_file() and p.name in ('LICENSE','PATENTS','NOTICE'):
            target=dest/'Go/vendor'/p.relative_to(goroot/'src/vendor')
            target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(p,target)
    shutil.copyfile(ROOT/'THIRD_PARTY_NOTICES.md',dest/'THIRD_PARTY_NOTICES.md')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--windows-host', required=True, help='Existing SSH host with Windows Framework csc.exe')
    ap.add_argument('--private-build', action='store_true', help='Use local service configuration and write to dist/private')
    args = ap.parse_args()
    vk_source = 'native/KindlyTurn/Source/pkg/clientcore/vk-apps.json'
    if not args.private_build and (ROOT / vk_source).read_text().strip() != '[]':
        raise ValueError('Public builds require an empty bundled VK application list')
    if not args.private_build:
        ENV.update(GOENV='off', GOFLAGS='')
    metadata = build_metadata()
    metadata['distribution'] = 'private' if args.private_build else 'public'
    metadata['csharpCompiler'] = ps(args.windows_host, r"[Diagnostics.FileVersionInfo]::GetVersionInfo((Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe')).FileVersion", capture_output=True, text=True).stdout.strip()
    run(['python3', str(ROOT / 'tools/prepare_native.py')])
    dist = ROOT / 'dist'
    if args.private_build:
        dist /= 'private'
    dest = dist / NAME
    dest.mkdir(parents=True, exist_ok=True)
    overrides = {}
    if args.private_build:
        for config, source in (
            ('panel-bootstrap.json', 'native/CombinedXray/internal/desktop/bootstrap.json'),
            ('vk-apps.json', vk_source),
        ):
            filename = ROOT / '.private' / config
            if filename.is_file():
                if not 2 <= filename.stat().st_size <= 32768:
                    raise ValueError('Invalid local configuration size')
                overrides[str(ROOT / source)] = str(filename)
    build_options = []
    if overrides:
        overlay = ROOT / '.build' / 'source-overlay.json'
        overlay.write_text(json.dumps({'Replace': overrides}))
        build_options.append('-overlay=' + str(overlay))
    linker = f"-s -w -X kindlyvpn/native/internal/desktop.Version={metadata['version']} -X kindlyvpn/native/internal/desktop.Build={metadata['buildId']}"
    run(['go','-C',str(ENGINE),'build','-mod=readonly',*build_options,'-trimpath','-ldflags='+linker,'-o',str(dest/'TnDtun.Engine.exe'),'./cmd/tndtun-engine'])
    assembly = ROOT / '.build' / 'AssemblyInfo.cs'
    assembly.write_text('using System.Reflection;\n'+''.join(f'[assembly: {key}({json.dumps(value)})]\n' for key, value in {
        'AssemblyTitle': PROJECT['name'], 'AssemblyProduct': PROJECT['name'],
        'AssemblyVersion': PROJECT['fileVersion'], 'AssemblyFileVersion': PROJECT['fileVersion'],
        'AssemblyInformationalVersion': metadata['version']+'+'+metadata['buildId'],
    }.items()))
    remote = 'AppData/Local/TnDtunBuild/preview1'
    ps(args.windows_host, "$ErrorActionPreference='Stop'; New-Item -ItemType Directory -Force (Join-Path $env:LOCALAPPDATA 'TnDtunBuild\\preview1') | Out-Null")
    run(['scp','-Cq',str(ROOT/'app/TnDtun.cs'),str(ROOT/'app/app.manifest'),str(ROOT/'resources/TnDtun.ico'),str(assembly),args.windows_host+':'+remote+'/'])
    ps(args.windows_host, r"""$ErrorActionPreference='Stop';$p=Join-Path $env:LOCALAPPDATA 'TnDtunBuild\preview1';$a=@('/nologo','/target:winexe','/platform:x64','/optimize+',('/out:'+(Join-Path $p 'TnDtun.exe')),('/win32manifest:'+(Join-Path $p 'app.manifest')),('/win32icon:'+(Join-Path $p 'TnDtun.ico')),'/reference:System.Windows.Forms.dll','/reference:System.Drawing.dll','/reference:System.Web.Extensions.dll','/reference:System.Web.dll',(Join-Path $p 'TnDtun.cs'),(Join-Path $p 'AssemblyInfo.cs')); & (Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe') @a;exit $LASTEXITCODE""")
    run(['scp','-Cq',args.windows_host+':'+remote+'/TnDtun.exe',str(dest/'TnDtun.exe')])
    for name in ('wintun.dll','WINTUN-LICENSE.txt','TnDtun.ico'):
        shutil.copyfile(ROOT/'resources'/name,dest/name)
    assert sha(dest/'wintun.dll') == 'e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce', 'Unexpected Wintun DLL'
    licenses()
    for name in ('LICENSE','START-RU.md','Install-Shortcuts.ps1','Remove-Shortcuts.ps1'):
        shutil.copyfile(ROOT/name,dest/name)
    shutil.copyfile(ROOT/'validation/SUMMARY.md',dest/'VALIDATION.md')
    if (dest/'licenses').exists(): shutil.rmtree(dest/'licenses')
    shutil.copytree(ROOT/'licenses',dest/'licenses')
    (dest/'BUILD-INFO.json').write_text(json.dumps(metadata, ensure_ascii=False, indent=2)+'\n')
    hashes = {str(p.relative_to(dest)):sha(p) for p in sorted(dest.rglob('*')) if p.is_file() and p.name!='SHA256SUMS.txt'}
    (dest/'SHA256SUMS.txt').write_text(''.join(f'{v}  {k}\n' for k,v in hashes.items()))
    output = dist / (NAME+'.zip');archive(dest,output,NAME)
    source = dist / (NAME+'-source.zip')
    allowed = ('app','tools','native','patches','resources','licenses','.build','.vscode')
    with zipfile.ZipFile(source,'w',zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        files = [p for name in allowed for p in (ROOT/name).rglob('*') if p.is_file()]
        files += [p for p in ROOT.iterdir() if p.is_file()]
        files += [ROOT/'validation/SUMMARY.md']
        for p in sorted(files):
            if p.name == 'source-overlay.json' or any(v in p.parts for v in ('__pycache__','.git','build-tools')) or p.suffix in ('.pyc','.exe','.log'):
                continue
            z.write(p,str(Path('TnDtun-Windows-source')/p.relative_to(ROOT)))
    checksum = f'{sha(output)}  {output.name}\n'
    output.with_suffix('.zip.sha256').write_text(checksum)
    (dist / 'SHA256SUMS.txt').write_text(checksum + f'{sha(source)}  {source.name}\n')
    (dist / 'last-build.json').write_text(json.dumps(dict(metadata, artifact=str(output), sha256=sha(output), bytes=output.stat().st_size), ensure_ascii=False, indent=2)+'\n')
    print(json.dumps({'app':str(output),'app_bytes':output.stat().st_size,'source':str(source),'source_bytes':source.stat().st_size},ensure_ascii=False,indent=2))


if __name__=='__main__': main()
