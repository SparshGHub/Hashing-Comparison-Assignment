from pathlib import Path
from typing import List

import typer
from tqdm import tqdm

from hashing import md5_hex, sha1_hex, sha256_hex
from utils import iter_files, file_size, make_tampered_copy, render_table


app = typer.Typer(add_completion=False, no_args_is_help=True)


def _row(p: Path):
    return {
        "File": str(p),
        "Size(bytes)": file_size(p),
        "MD5": md5_hex(p),
        "SHA-1": sha1_hex(p),
        "SHA-256": sha256_hex(p),
    }


@app.command(help="Compare MD5 / SHA-1 / SHA-256 for files/folders. Optionally add a tampered copy.")
def compare(
    inputs: List[str] = typer.Argument(..., help="Files or folders"),
    tamper: str = typer.Option("", help="Create a 1-bit-flipped copy of this file and include it"),
    index: int = typer.Option(0, help="Byte index to flip in tampered copy (default 0)"),
):
    files = list(iter_files(inputs))
    if tamper:
        src = Path(tamper)
        if not src.exists():
            typer.secho(f"[error] --tamper not found: {src}", fg=typer.colors.RED)
            raise typer.Exit(2)
        t = src.with_name(src.stem + "_tampered" + src.suffix)
        make_tampered_copy(src, t, index)
        files.append(t)

    if not files:
        typer.secho("No files found.", fg=typer.colors.RED)
        raise typer.Exit(2)

    rows = []
    for p in tqdm(files, desc="Hashing", unit="file"):
        rows.append(_row(Path(p)))

    render_table(rows)


if __name__ == "__main__":
    app()
