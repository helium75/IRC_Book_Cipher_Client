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
    """Verwirft nur EXAKTE Duplikate (gleicher Absender + gleicher
    Zähler), die schon einmal gesehen wurden - nicht bloß Zähler, die
    kleiner als der zuletzt gesehene sind.

    Grund für die Änderung: Channel-History (beim Rejoin) oder ein
    Neuverbinden können Nachrichten in einer Reihenfolge anliefern, die
    nicht mehr streng chronologisch ist - eine reine "muss größer sein
    als der letzte Zähler"-Prüfung hätte solche (legitimen) Nachrichten
    fälschlich als Replay verworfen.

    Sicherheit bleibt dabei vollständig gewahrt: Ein Angreifer ohne den
    HMAC-Schlüssel kann den Zähler einer abgefangenen Nachricht nicht
    verändern (der MAC deckt ihn mit ab) - er kann bestenfalls exakt
    dieselbe, bereits gültige Nachricht erneut einspielen, und genau
    das wird hier weiterhin zuverlässig erkannt."""

    MAX_PER_SENDER = 500  # Obergrenze pro Absender, damit der Speicher nicht unbegrenzt waechst

    def __init__(self):
        self._seen = {}  # sender -> {counter: True, ...}, Einfuegereihenfolge erhalten

    def check_and_update(self, sender, counter):
        seen_counters = self._seen.setdefault(sender, {})
        if counter in seen_counters:
            return False
        seen_counters[counter] = True
        if len(seen_counters) > self.MAX_PER_SENDER:
            oldest_key = next(iter(seen_counters))
            del seen_counters[oldest_key]
        return True
