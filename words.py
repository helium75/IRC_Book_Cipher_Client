import random
import sys
from pathlib import Path

def make_text(min_length=80000, min_count_per_char=100, newline_ratio=0.02, space_ratio=0.12):
    # Basiszeichen: Latin-1 32..255 (druckbar; enthält Umlaute & Sonderzeichen)
    base_chars = [chr(b) for b in range(32, 256)]
    pool = []
    for c in base_chars:
        pool.extend([c] * min_count_per_char)
    # Füge zusätzlich Leerzeichen und Newlines gezielt in Pool ein (um Verteilung zu gewährleisten)
    # space_ratio und newline_ratio sind Anteile an der Gesamtlänge (ungefähr)
    target_extra = max(0, min_length - len(pool))
    # berechne gewünschte Anzahl spaces/newlines aus target_extra
    n_spaces = int(target_extra * space_ratio)
    n_newlines = int(target_extra * newline_ratio)
    pool.extend([' '] * n_spaces)
    pool.extend(['\n'] * n_newlines)
    # Auffüllen bis min_length mit zufälligen Basiszeichen, Spaces oder Newlines
    choices = base_chars + [' ', '\n']
    while len(pool) < min_length:
        pool.append(random.choice(choices))
    random.shuffle(pool)
    return ''.join(pool)

def main():
    if len(sys.argv) != 2:
        print("Usage: python make_large_text_with_newlines.py <output.txt>")
        sys.exit(1)
    out_path = Path(sys.argv[1])
    text = make_text(min_length=80000, min_count_per_char=100, newline_ratio=0.02, space_ratio=0.12)
    out_path.write_text(text, encoding='utf-8')
    print(f"Wrote {len(text)} characters to {out_path}")

if __name__ == "__main__":
    main()
