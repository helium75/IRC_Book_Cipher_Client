# Cipher IRC Messenger

Ein IRC-Chatclient mit deiner homophonen Buchchiffre. Nutzt nur die
Python-Standardbibliothek (socket, ssl, tkinter) - läuft unverändert
unter Windows, Linux und macOS, keine Zusatzpakete zum Ausführen nötig.

## Dateien

| Datei              | Zweck                                                        |
|---------------------|---------------------------------------------------------------|
| `cipher.py`         | Kern-Chiffre (Base62-Kodierung statt Dezimal+Komma)           |
| `irc_client.py`      | IRC-Verbindung per Socket (mit TLS)                            |
| `chat_protocol.py`   | Teilt Ciphertext in IRC-taugliche Zeilen, setzt sie wieder zusammen |
| `auth.py`            | HMAC-Integritätsprüfung + Replay-Schutz über Zähler             |
| `gui.py`             | Tkinter-Fenster, Startpunkt des Programms                      |

## Nutzung

1. Codebuch erzeugen (mit deinem vorhandenen Skript, hier `words.py`
   genannt) und **sicher** (nicht über IRC selbst!) an alle Chatpartner
   verteilen, z.B. per USB-Stick oder anderem verschlüsseltem Kanal:

   ```
   python words.py codebuch.txt
   ```

2. Client starten:

   ```
   python gui.py
   ```

3. Zusätzlich zum Codebuch braucht ihr einen **zweiten, separaten
   geheimen Schlüssel** (den "HMAC-Schlüssel") - ein beliebiges Passwort,
   das ebenfalls sicher unter allen Chatpartnern geteilt werden muss.
   Er darf NICHT identisch mit dem Codebuch sein, sonst hängt die
   Integritätsprüfung am selben Geheimnis wie die Verschlüsselung.

4. Im Fenster: Server, Port, Nick, Channel eintragen, `codebuch.txt`
   auswählen, HMAC-Schlüssel eingeben, "Verbinden" klicken. Alle
   Nachrichten im Chatfenster werden automatisch ver-/entschlüsselt
   UND auf Integrität geprüft. Nachrichten von Nutzern ohne dasselbe
   Codebuch (oder normale IRC-Statusmeldungen) werden nicht als
   Klartext angezeigt, da sie nicht dem `CMSG:`-Format entsprechen.

## Wie der Integritätsschutz funktioniert

Vor der Verschlüsselung wird jede Nachricht in ein Bundle verpackt:

```
<zaehler>:<hmac>:<nachrichtentext>
```

- **zaehler**: Millisekunden-Zeitstempel, muss beim Empfänger pro
  Absender strikt aufsteigend sein - ältere/wiederholte Zähler werden
  verworfen (Replay-Schutz).
- **hmac**: HMAC-SHA256 über Zähler + Absender-Nick + Nachricht,
  berechnet mit dem separaten HMAC-Schlüssel. Deckt die *gesamte*
  Nachricht ab, nicht einzelne Zeichen - jede Manipulation oder jedes
  Zusammenkleben alter Ciphertext-Fragmente führt zu einem ungültigen
  HMAC und wird beim Empfänger verworfen (in der Oberfläche mit ⚠
  markiert).

Erst danach wird das gesamte Bundle mit dem Buchchiffre verschlüsselt
und wie gehabt in Chunks verschickt.

## Windows .exe bauen (PyInstaller)

Du brauchst kein "python2bin" - das Standardwerkzeug dafür ist
PyInstaller, funktioniert auch, wenn du unter Linux/Mac entwickelst und
nur unter Windows testest/baust (PyInstaller muss aber auf einer
Windows-Maschine laufen, um eine .exe zu erzeugen - Cross-Compiling von
Linux nach Windows funktioniert damit nicht direkt).

Auf einer Windows-Maschine mit installiertem Python:

```
pip install pyinstaller
pyinstaller --onefile --windowed --name CipherIRC gui.py
```

Ergebnis liegt danach in `dist\CipherIRC.exe` - eine einzelne
Datei ohne weitere Abhängigkeiten, die du an deine Nutzer verteilen
kannst.

## Wichtige Einschränkungen (bitte lesen)

- **Metadaten sind ungeschützt.** Der IRC-Server (und jeder, der den
  Traffic mitschneidet) sieht weiterhin, wer mit wem wann kommuniziert,
  auch wenn der Inhalt unlesbar ist.
- **Codebuch-Verteilung ist der Sicherheitsanker.** Wird das Codebuch
  kompromittiert, ist die gesamte bisherige und zukünftige
  Kommunikation mit diesem Buch lesbar. Kein Forward Secrecy.
- **Kein Peer-Review.** Das ist ein selbstgebauter Chiffre-Algorithmus.
  Für tatsächlich sensible Kommunikation (nicht nur zum Lernen/Basteln)
  würde ich immer etablierte, geprüfte Verfahren empfehlen.
- **Der Replay-Schutz basiert auf der Systemuhr.** Der Zähler ist ein
  Zeitstempel in Millisekunden. Läuft die Uhr eines Teilnehmers stark
  falsch (z.B. massiv zurückgestellt), könnten dessen Nachrichten vom
  ReplayGuard fälschlich als "alt" verworfen werden. Für den
  Normalbetrieb unkritisch, aber gut zu wissen.
- **Der HMAC-Schlüssel wird aktuell im Klartext im Eingabefeld
  gehalten** (nur maskiert dargestellt) und nicht sicher aus dem
  Speicher gelöscht. Für ein Hobby-/Lernprojekt unkritisch, für echten
  Einsatz gegen starke Angreifer wäre ein sichereres Schlüssel-Handling
  (z.B. über ein Betriebssystem-Schlüsselverwaltungs-API) sinnvoller.
