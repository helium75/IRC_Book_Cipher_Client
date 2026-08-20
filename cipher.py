"""
cipher.py - Homophoner Buchchiffre auf Basis eines gemeinsamen Codebuchs.

Beide Kommunikationspartner brauchen exakt dieselbe Codebuch-Datei
(z.B. erzeugt mit dem vorhandenen words.py-Skript).

Kodierung: Jede Zeichenposition im Codebuch wird als Base62-Zahl fester
Breite dargestellt. Dadurch braucht man KEIN Trennzeichen zwischen den
kodierten Positionen (im Gegensatz zum Komma-getrennten Original), was
die Ciphertext-Länge spürbar reduziert - wichtig wegen der 512-Byte-
Zeilenbegrenzung von IRC.

Beispiel: bei einem 80.000 Zeichen langen Codebuch braucht man nur
3 Base62-Stellen pro Zeichen (62^3 = 238.328 > 80.000) statt 5-6 Stellen
Dezimalzahl + Komma wie im Original-Skript.
"""

import random
import math
from pathlib import Path

BASE62_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
BASE = len(BASE62_ALPHABET)
_DIGIT_VALUE = {ch: i for i, ch in enumerate(BASE62_ALPHABET)}


def load_codebook(path, encoding="utf-8"):
    return Path(path).read_text(encoding=encoding)


def _width_for_length(length):
    """Anzahl Base62-Stellen, um jeden Index in [0, length) darstellen zu können."""
    if length <= 1:
        return 1
    return max(1, math.ceil(math.log(length, BASE)))


def build_index_map(codebook):
    index = {}
    for i, ch in enumerate(codebook):
        index.setdefault(ch, []).append(i)
    return index


def _encode_int(n, width):
    digits = []
    for _ in range(width):
        n, r = divmod(n, BASE)
        digits.append(BASE62_ALPHABET[r])
    if n != 0:
        raise ValueError("Position zu groß für konfigurierte Breite - falsches Codebuch?")
    return "".join(reversed(digits))


def _decode_int(s):
    n = 0
    for ch in s:
        n = n * BASE + _DIGIT_VALUE[ch]
    return n


class Cipher:
    """Verschlüsselt/entschlüsselt Text mithilfe eines gemeinsamen Codebuchs."""

    def __init__(self, codebook_text):
        if not codebook_text:
            raise ValueError("Codebuch ist leer")
        self.codebook = codebook_text
        self.length = len(codebook_text)
        self.width = _width_for_length(self.length)
        self.index_map = build_index_map(codebook_text)

    def encrypt(self, plaintext):
        out = []
        for ch in plaintext:
            positions = self.index_map.get(ch)
            if not positions:
                raise ValueError(f"Zeichen nicht im Codebuch enthalten: {ch!r}")
            pos = random.choice(positions)
            out.append(_encode_int(pos, self.width))
        return "".join(out)

    def decrypt(self, ciphertext):
        if len(ciphertext) % self.width != 0:
            raise ValueError(
                "Ciphertext-Länge kein Vielfaches der Codebuch-Breite "
                "- falsches Codebuch oder beschädigte Daten"
            )
        chars = []
        for i in range(0, len(ciphertext), self.width):
            chunk = ciphertext[i:i + self.width]
            pos = _decode_int(chunk)
            if pos < 0 or pos >= self.length:
                raise ValueError(f"Dekodierte Position außerhalb des Bereichs: {pos}")
            chars.append(self.codebook[pos])
        return "".join(chars)
