#!/usr/bin/env python3
import argparse, html, json, re, shutil
from pathlib import Path

PATTERNS={
 'email': re.compile(r'\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b',re.I),
 'phone_like': re.compile(r'(?<!\d)(?:\+?81[- ]?)?0\d{1,4}[- ]?\d{1,4}[- ]?\d{3,4}(?!\d)'),
 'secret_like': re.compile(r'(?:sk-[A-Za-z0-9_-]{16,}|ghp_[A-Za-z0-9]{16,}|(?:api[_-]?key|token|secret|password)\s*[:=]\s*["\']?[^\s"\']{8,})',re.I),
 'private_ip': re.compile(r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b'),
 'home_path': re.compile(r'(?:/home/[A-Za-z0-9._-]+|/Users/[A-Za-z0-9._-]+|[A-Z]:\\Users\\[^\\\s]+)',re.I),
 'draft_marker': re.compile(r'\b(?:TODO|FIXME|DRAFT|WIP|PLACEHOLDER)\b',re.I),
}
TEXT_SUFFIXES={'.md','.txt','.html','.css','.js','.json','.yaml','.yml','.toml','.ini','.py','.csv','.tsv'}

def iter_files(root):
    root=Path(root)
    if root.is_file(): yield root; return
    for p in root.rglob('*'):
        if p.is_symlink():
            continue
        if p.is_file() and p.suffix.lower() in TEXT_SUFFIXES and '.git' not in p.parts:
            yield p
def scan(root):
    findings=[]; files=0
    for p in iter_files(root):
        try: text=p.read_text(encoding='utf-8')
        except (UnicodeDecodeError,OSError): continue
        files+=1
        for kind,rx in PATTERNS.items():
            for m in rx.finditer(text):
                line=text.count('\n',0,m.start())+1
                preview=m.group(0)
                if kind in {'email','phone_like','secret_like'}: preview=preview[:6]+'…'
                findings.append({'kind':kind,'path':str(p),'line':line,'preview':preview[:80]})
    return {'files':files,'findings':findings,'counts':{k:sum(1 for f in findings if f['kind']==k) for k in PATTERNS}}

def redact_text(text):
    for kind,rx in PATTERNS.items():
        if kind=='draft_marker': continue
        text=rx.sub(f'<redacted:{kind}>',text)
    return text

def redact_copy(src,dst):
    src=Path(src); dst=Path(dst)
    src_abs=src.resolve()
    dst_abs=dst.resolve(strict=False)
    if src.is_file():
        if dst_abs == src_abs:
            raise ValueError('redact-out must not overwrite the source file')
        dst.parent.mkdir(parents=True,exist_ok=True); dst.write_text(redact_text(src.read_text(encoding='utf-8')),encoding='utf-8'); return 1
    if dst_abs == src_abs or src_abs in dst_abs.parents:
        raise ValueError('redact-out must be outside the source directory')
    count=0
    for p in iter_files(src):
        rel=p.relative_to(src); out=dst/rel; out.parent.mkdir(parents=True,exist_ok=True)
        try: out.write_text(redact_text(p.read_text(encoding='utf-8')),encoding='utf-8'); count+=1
        except UnicodeDecodeError: pass
    return count
def render(report):
    rows=''.join(f"<tr><td>{html.escape(f['kind'])}</td><td>{html.escape(f['path'])}</td><td>{f['line']}</td><td>{html.escape(f['preview'])}</td></tr>" for f in report['findings'])
    counts=' · '.join(f'{k}:{v}' for k,v in report['counts'].items())
    return f'''<!doctype html><meta charset="utf-8"><title>Share Safe Pack</title><style>body{{font:15px system-ui;max-width:1000px;margin:auto;padding:40px;background:#f2ece4;color:#292421}}.summary{{background:#fffaf2;padding:18px;border:1px solid #ddd1c4}}table{{width:100%;border-collapse:collapse;background:#fffaf2;margin-top:18px}}td,th{{padding:9px;border-bottom:1px solid #ddd;text-align:left}}</style><h1>Share Safe Pack</h1><div class="summary">scanned {report['files']} files · {len(report['findings'])} findings<br>{html.escape(counts)}</div><table><tr><th>kind</th><th>path</th><th>line</th><th>preview</th></tr>{rows}</table>'''

def main():
    ap=argparse.ArgumentParser(description='Check a folder before publishing or sharing it.')
    ap.add_argument('path'); ap.add_argument('--html',default='share-safe-report.html')
    ap.add_argument('--json'); ap.add_argument('--redact-out')
    a=ap.parse_args(); report=scan(a.path)
    Path(a.html).write_text(render(report),encoding='utf-8')
    if a.json: Path(a.json).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    copied=redact_copy(a.path,a.redact_out) if a.redact_out else 0
    print(f"files={report['files']} findings={len(report['findings'])} redacted_files={copied}")

if __name__=='__main__':
    main()
