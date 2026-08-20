"""
auth.py - Nachrichtenauthentifizierung mit HMAC-SHA256 + Zähler.

Schützt gegen:
  - Manipulation des Ciphertexts (Integrität)
  - Replay-Angriffe (durch einen monoton steigenden Zähler)
  - Splicing / Zusammenkleben alter Nachrichtenteile (der MAC deckt die
    GESAMTE Nachricht inkl. Zähler und Absender ab, nicht einzelne
    Zeichen)

WICHTIG: Der HMAC-Schlüssel ist ein zweites Geheimnis, zusätzlich zum
Codebuch. Beide Parteien müssen ihn kennen, aber er sollte NICHT mit
dem Codebuch identisch sein (sonst hängt die Sicherheit beider
Mechanismen am selben Geheimnis).
"""

import hmac
import hashlib
import time


def compute_mac(key, counter, sender, message):
    """Berechnet den HMAC über Zähler + Absender + Nachricht.

    Durch die Einbeziehung von sender und counter kann ein Angreifer
    weder eine Nachricht einem anderen Absender unterschieben noch
    eine alte Nachricht unverändert erneut einspielen (siehe
    verify_mac / ReplayGuard)."""
    payload = f"{counter}|{sender}|{message}".encode("utf-8")
    return hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def verify_mac(key, counter, sender, message, mac):
    expected = compute_mac(key, counter, sender, message)
    # compare_digest verhindert Timing-Angriffe beim Vergleich
    return hmac.compare_digest(expected, mac)


def new_counter():
    """Millisekunden-Zeitstempel als Zähler - monoton steigend, auch
    über Programmneustarts hinweg (solange die Systemuhr stimmt)."""
    return int(time.time() * 1000)


class ReplayGuard:
    """Merkt sich pro Absender den zuletzt akzeptierten Zähler und
    verwirft alles, was nicht strikt größer ist."""

    def __init__(self):
        self._last_seen = {}

    def check_and_update(self, sender, counter):
        last = self._last_seen.get(sender, -1)
        if counter <= last:
            return False
        self._last_seen[sender] = counter
        return True
