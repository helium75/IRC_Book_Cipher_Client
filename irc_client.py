"""
irc_client.py - Minimaler IRC-Client (reine Standardbibliothek, KEIN
externes Paket noetig, auch nicht fuer TLS-Zertifikatspruefung).
Laeuft unter Windows/Linux/Mac identisch.
"""

import socket
import ssl
import threading

# ISRG Root X1 - das aktuelle, selbstsignierte Let's-Encrypt-Stammzertifikat
# (gueltig bis 04.06.2035). Direkt eingebettet statt per Zusatzpaket (certifi)
# nachzuladen: manche Windows-Installationen halten ihren eigenen
# Zertifikatsspeicher nicht zuverlaessig aktuell und verankern dort noch
# einen laengst abgelaufenen alten Root ("DST Root CA X3", abgelaufen seit
# 2021), was bei der Kettenpruefung faelschlich zu "certificate has expired"
# fuehren kann - obwohl das eigentliche Server-Zertifikat voellig gueltig
# ist. Dieses eingebettete Zertifikat wird dem Standard-Vertrauensspeicher
# zusaetzlich hinzugefuegt (nicht anstelle davon), um dieses Problem
# zuverlaessig zu umgehen, ganz ohne pip install.
#
# Quelle/Fingerabdruck zum Abgleich: https://letsencrypt.org/certs/isrgrootx1.pem
# SHA256 Fingerprint: 96:BC:EC:06:26:49:76:F3:74:60:77:9A:CF:28:C5:A7:
#                      CF:E8:A3:C0:AA:E1:1A:8F:FC:EE:05:C0:BD:DF:08:C6
ISRG_ROOT_X1_PEM = """-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----
"""


class IRCClient:
    def __init__(self, server, port, nickname, use_tls=True,
                 on_message=None, on_status=None):
        self.server = server
        self.port = port
        self.nickname = nickname
        self.use_tls = use_tls
        self.on_message = on_message or (lambda *a, **k: None)
        self.on_status = on_status or (lambda *a, **k: None)
        self.sock = None
        self._recv_thread = None
        self._running = False
        self._buffer = ""

    def connect(self):
        raw_sock = socket.create_connection((self.server, self.port), timeout=15)
        # WICHTIG: create_connection() hinterlaesst den connect-Timeout (15s)
        # dauerhaft auf dem Socket. Ohne den Reset auf None wuerde jeder
        # recv()-Aufruf nach 15s Inaktivitaet (z.B. zwischen zwei PINGs)
        # eine socket.timeout-Exception werfen, die faelschlich als
        # "Verbindung tot" behandelt wurde - der Client haerte lokal auf
        # zuzuhoeren, obwohl die Verbindung intakt war, konnte PING nicht
        # mehr beantworten, und wurde dann vom Server nach dessen eigenem
        # Ping-Timeout (typischerweise 180s) getrennt.
        raw_sock.settimeout(None)
        if self.use_tls:
            self.sock = self._tls_wrap_with_fallback(raw_sock)
        else:
            self.sock = raw_sock
        self._running = True
        self._send_raw("CAP LS 302")
        self._send_raw("CAP REQ :server-time")
        self._send_raw("CAP END")
        self._send_raw(f"NICK {self.nickname}")
        self._send_raw(f"USER {self.nickname} 0 * :{self.nickname}")
        self._recv_thread = threading.Thread(target=self._recv_loop, daemon=True)
        self._recv_thread.start()

    def _tls_wrap_with_fallback(self, raw_sock):
        """Baut die TLS-Verbindung auf - mit automatischem Fallback bei
        Zertifikatsfehlern.

        1. Versuch: Standard-Kontext (Betriebssystem-Speicher, ergaenzt
           um unser eingebettetes ISRG-Root-X1-Zertifikat).
        2. Versuch (nur falls Versuch 1 mit einem Zertifikatsfehler
           scheitert): Ein Kontext, der AUSSCHLIESSLICH unser
           eingebettetes, bekanntermassen korrektes Root-Zertifikat
           nutzt - der Betriebssystem-Speicher wird dabei komplett
           umgangen.

        Hintergrund: manche (v.a. Windows-)Zertifikatsspeicher enthalten
        zusaetzliche, teils veraltete Eintraege. Bei laengeren oder
        ungewoehnlichen Zertifikatsketten (wie sie manche aktuellen
        Let's-Encrypt-Auslieferungen inzwischen verwenden) kann die
        zugrunde liegende TLS-Bibliothek dadurch faelschlich einen
        fehlerhaften alternativen Pfad probieren und mit "certificate
        has expired" abbrechen, OBWOHL die vom Server tatsaechlich
        gesendete Kette komplett gueltig ist und ueber unser
        eingebettetes Root aufloesbar waere. Das ist kein neues Problem,
        sondern historisch v.a. rund um den Ablauf von "DST Root CA X3"
        2021 breit aufgetreten. Der zweite Versuch mit einem "sauberen",
        auf unser eigenes Root beschraenkten Kontext umgeht das
        zuverlaessig, ohne die allgemeine Kompatibilitaet zu anderen
        IRC-Servern (mit anderen Zertifizierungsstellen) einzuschraenken,
        da er nur als Fallback greift."""
        primary_ctx = ssl.create_default_context()
        try:
            primary_ctx.load_verify_locations(cadata=ISRG_ROOT_X1_PEM)
        except ssl.SSLError:
            pass

        try:
            return primary_ctx.wrap_socket(raw_sock, server_hostname=self.server)
        except ssl.SSLCertVerificationError:
            pass

        # Fallback: sauberer Kontext, NUR unser eingebettetes Root.
        # Der alte Socket ist nach einem gescheiterten TLS-Handshake
        # nicht mehr benutzbar - frische TCP-Verbindung fuer den
        # zweiten Versuch aufbauen.
        try:
            raw_sock.close()
        except OSError:
            pass
        retry_sock = socket.create_connection((self.server, self.port), timeout=15)
        retry_sock.settimeout(None)

        fallback_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        fallback_ctx.load_verify_locations(cadata=ISRG_ROOT_X1_PEM)
        return fallback_ctx.wrap_socket(retry_sock, server_hostname=self.server)

    def join(self, channel):
        self._send_raw(f"JOIN {channel}")

    def send_privmsg(self, target, text):
        self._send_raw(f"PRIVMSG {target} :{text}")

    def _send_raw(self, line):
        data = (line + "\r\n").encode("utf-8", errors="replace")
        self.sock.sendall(data)

    def _recv_loop(self):
        while self._running:
            try:
                data = self.sock.recv(4096)
            except OSError:
                break
            if not data:
                break
            self._buffer += data.decode("utf-8", errors="replace")
            while "\r\n" in self._buffer:
                line, self._buffer = self._buffer.split("\r\n", 1)
                self._handle_line(line)
        self._running = False
        self.on_status("disconnected")

    def _handle_line(self, line):
        # IRCv3 Message Tags: optionaler @tag1=wert;tag2=wert Praefix vor
        # der eigentlichen Zeile - kommt z.B. durch die server-time CAP
        # zustande, die wir fuer die Channel-History-Wiedergabe brauchen.
        # Muss vor allem anderen Parsing abgeschnitten werden.
        if line.startswith("@"):
            space_idx = line.find(" ")
            if space_idx == -1:
                return  # nur Tags ohne eigentliche Nachricht - ignorieren
            line = line[space_idx + 1:]

        if line.startswith("PING"):
            self._send_raw("PONG" + line[4:])
            return
        if " PRIVMSG " in line:
            try:
                prefix, rest = line[1:].split(" PRIVMSG ", 1)
                sender = prefix.split("!")[0]
                target, msg = rest.split(" :", 1)
                self.on_message(sender, target, msg)
            except ValueError:
                pass
        elif " 001 " in line:
            self.on_status("Verbunden (Welcome empfangen)")
        elif " 433 " in line:
            self.on_status("Nickname bereits vergeben!")
        else:
            self.on_status(line)

    def send_raw(self, line):
        """Sendet eine rohe IRC-Protokollzeile unveraendert - fuer Slash-Befehle
        wie /join, /nick, /part, die der Server direkt verstehen muss und
        die daher NICHT durch den Chiffre geschickt werden duerfen."""
        self._send_raw(line)

    def close(self):
        self._running = False
        try:
            self._send_raw("QUIT :bye")
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass
