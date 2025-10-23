from pathlib import Path

def iter_files(inputs):
    seen=set()
    for p in map(Path, inputs):
        if p.is_file():
            r=p.resolve()
            if r not in seen: seen.add(r); yield r
        elif p.is_dir():
            for f in p.rglob("*"):
                if f.is_file() and f.name not in (".DS_Store","Thumbs.db"):
                    r=f.resolve()
                    if r not in seen: seen.add(r); yield r

def file_size(p: Path) -> int:
    return p.stat().st_size

def make_tampered_copy(src: Path, dst: Path, byte_index: int = 0):
    data=bytearray(src.read_bytes())
    if not data: data+=b"\x00"
    i=max(0,min(byte_index,len(data)-1))
    data[i]^=0x01  # flip 1 bit
    dst.write_bytes(data)
    return dst

def render_table(rows):
    try:
        from tabulate import tabulate
        print(tabulate(rows, headers="keys", tablefmt="github"))
    except Exception:
        headers=list(rows[0].keys()); w={h:len(h) for h in headers}
        for r in rows:
            for h in headers: w[h]=max(w[h],len(str(r[h])))
        def line(sep="+",fill="-"): print(sep+sep.join(fill*(w[h]+2) for h in headers)+sep)
        def row(vals): print("| "+" | ".join(str(vals[h]).ljust(w[h]) for h in headers)+" |")
        line(); row({h:h for h in headers}); line()
        for r in rows: row(r)
        line()
