"""
gui.py - Chat-Fenster (Tkinter) fuer den Cipher-IRC-Messenger.

Start: python gui.py
Braucht nur die Python-Standardbibliothek -> laeuft unveraendert unter
Windows, Linux und macOS. Fuer eine eigenstaendige .exe siehe README.md.
"""

import queue
import re
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

from cipher import Cipher, load_codebook
from irc_client import IRCClient
from chat_protocol import frame_message, Reassembler
from auth import compute_mac, verify_mac, new_counter, ReplayGuard


class ChatApp:
    def __init__(self, root):
        self.root = root
        root.title("Cipher IRC Messenger")

        self.client = None
        self.cipher = None
        self.reassembler = Reassembler()
        self.channel = None
        self.event_queue = queue.Queue()
        self.auth_key = None
        self.replay_guard = ReplayGuard()
        self.my_nick = None
        self._joined = False

        self._build_connect_frame()
        self._build_chat_frame()
        self.root.after(100, self._poll_queue)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ---------- UI Aufbau ----------

    def _build_connect_frame(self):
        frame = tk.Frame(self.root)
        frame.pack(fill="x", padx=6, pady=6)

        tk.Label(frame, text="Server").grid(row=0, column=0, sticky="e")
        self.server_var = tk.StringVar(value="irc.libera.chat")
        tk.Entry(frame, textvariable=self.server_var, width=25).grid(row=0, column=1)

        tk.Label(frame, text="Port").grid(row=0, column=2, sticky="e")
        self.port_var = tk.StringVar(value="6697")
        tk.Entry(frame, textvariable=self.port_var, width=6).grid(row=0, column=3)

        self.tls_var = tk.BooleanVar(value=True)
        tk.Checkbutton(frame, text="TLS", variable=self.tls_var).grid(row=0, column=4)

        self.notify_var = tk.BooleanVar(value=True)
        tk.Checkbutton(frame, text="Ton bei Nachricht", variable=self.notify_var).grid(
            row=1, column=4)

        tk.Label(frame, text="Nick").grid(row=1, column=0, sticky="e")
        self.nick_var = tk.StringVar(value="user")
        tk.Entry(frame, textvariable=self.nick_var, width=15).grid(row=1, column=1)

        tk.Label(frame, text="Channel").grid(row=1, column=2, sticky="e")
        self.channel_var = tk.StringVar(value="#mychannel")
        tk.Entry(frame, textvariable=self.channel_var, width=15).grid(row=1, column=3)

        tk.Label(frame, text="Codebuch").grid(row=2, column=0, sticky="e")
        self.codebook_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.codebook_var, width=30).grid(
            row=2, column=1, columnspan=2, sticky="we")
        tk.Button(frame, text="Durchsuchen...", command=self._browse_codebook).grid(row=2, column=3)

        tk.Label(frame, text="HMAC-Schlüssel").grid(row=3, column=0, sticky="e")
        self.auth_key_var = tk.StringVar()
        tk.Entry(frame, textvariable=self.auth_key_var, width=30, show="*").grid(
            row=3, column=1, columnspan=2, sticky="we")
        tk.Label(frame, text="(zweites Geheimnis, nicht = Codebuch)",
                 fg="gray").grid(row=3, column=3, columnspan=2, sticky="w")

        self.connect_btn = tk.Button(frame, text="Verbinden", command=self._connect)
        self.connect_btn.grid(row=4, column=3, padx=4)

        self.disconnect_btn = tk.Button(frame, text="Trennen", command=self._disconnect,
                                         state="disabled")
        self.disconnect_btn.grid(row=4, column=4, padx=4)

    def _build_chat_frame(self):
        self.chat_display = scrolledtext.ScrolledText(self.root, state="disabled", width=80, height=24)
        self.chat_display.pack(padx=6, pady=6)

        entry_frame = tk.Frame(self.root)
        entry_frame.pack(fill="x", padx=6, pady=(0, 6))
        self.msg_var = tk.StringVar()
        entry = tk.Entry(entry_frame, textvariable=self.msg_var)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda e: self._send())
        tk.Button(entry_frame, text="Senden", command=self._send).pack(side="left", padx=4)

    # ---------- Aktionen ----------

    def _browse_codebook(self):
        path = filedialog.askopenfilename(title="Codebuch-Datei waehlen")
        if path:
            self.codebook_var.set(path)

    def _log(self, text):
        self.chat_display.configure(state="normal")
        self.chat_display.insert("end", text + "\n")
        self.chat_display.configure(state="disabled")
        self.chat_display.see("end")

    def _connect(self):
        codebook_path = self.codebook_var.get().strip()
        if not codebook_path:
            messagebox.showerror("Fehler", "Bitte zuerst eine Codebuch-Datei waehlen.")
            return
        try:
            codebook_text = load_codebook(codebook_path)
            self.cipher = Cipher(codebook_text)
        except Exception as e:
            messagebox.showerror("Codebuch-Fehler", str(e))
            return

        auth_key = self.auth_key_var.get()
        if not auth_key:
            messagebox.showerror("Fehler", "Bitte einen HMAC-Schlüssel eingeben (zweites, "
                                            "separates Geheimnis - schützt vor Manipulation/Replay).")
            return
        self.auth_key = auth_key

        server = self.server_var.get().strip()
        try:
            port = int(self.port_var.get().strip())
        except ValueError:
            messagebox.showerror("Fehler", "Port muss eine Zahl sein.")
            return
        nick = self.nick_var.get().strip()
        self.my_nick = nick
        self.channel = self.channel_var.get().strip()

        self.client = IRCClient(
            server, port, nick,
            use_tls=self.tls_var.get(),
            on_message=self._on_irc_message,
            on_status=self._on_irc_status,
        )
        self._joined = False

        try:
            self.client.connect()
        except Exception as e:
            messagebox.showerror("Verbindungsfehler", str(e))
            return

        self.connect_btn.configure(state="disabled")
        self.disconnect_btn.configure(state="normal")
        self._log(f"* Verbinde zu {server}:{port} ...")

    def _disconnect(self):
        if self.client:
            self.client.close()
        self._reset_connection_state()
        self._log("* Verbindung getrennt.")

    def _reset_connection_state(self):
        """Setzt nur den Verbindungsstatus zurueck (Client, Join-Status,
        Buttons) - Codebuch, HMAC-Schluessel und Channel-Feld bleiben
        erhalten, damit ein erneutes Verbinden ohne alles neu Eintippen
        moeglich ist."""
        self.client = None
        self._joined = False
        self.connect_btn.configure(state="normal")
        self.disconnect_btn.configure(state="disabled")

    def _join_after_welcome(self):
        # Nicht mehr per fester Wartezeit genutzt (siehe _on_irc_status),
        # bleibt als Fallback erhalten falls jemand es direkt aufruft.
        if self.client and self.channel and not self._joined:
            self._joined = True
            self.client.join(self.channel)
            self.event_queue.put(("status", f"Channel {self.channel} beigetreten"))

    def _on_irc_status(self, status):
        self.event_queue.put(("status", status))
        # Sofort joinen, sobald der Server die Registrierung bestaetigt
        # (001-Antwort) - statt einer festen Wartezeit, die zu einer
        # Race Condition fuehren konnte: wer schneller tippte und sendete
        # als die Wartezeit, bekam ERR_NOEXTERNALMSG (404), weil der
        # JOIN serverseitig noch gar nicht angekommen war.
        if status.startswith("Verbunden") and self.channel and not self._joined:
            self._join_after_welcome()
        if status == "disconnected":
            # Kommt aus dem Empfangs-Thread - UI-Aenderungen (Buttons)
            # muessen ueber die Queue im Hauptthread laufen.
            self.event_queue.put(("reset_ui", None))

    def _on_irc_message(self, sender, target, text):
        self.event_queue.put(("msg", sender, target, text))

    def _poll_queue(self):
        try:
            while True:
                item = self.event_queue.get_nowait()
                if item[0] == "status":
                    self._log(f"* {item[1]}")
                elif item[0] == "msg":
                    _, sender, target, text = item
                    self._handle_incoming(sender, text)
                elif item[0] == "reset_ui":
                    self._reset_connection_state()
        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)

    def _handle_incoming(self, sender, text):
        if not text.startswith("CMSG:"):
            # Unverschluesselte Nachricht (z.B. Antwort eines Bots wie
            # notify_bot, der ja weder Codebuch noch HMAC-Schluessel
            # kennt und daher nur Klartext senden kann) - deutlich
            # markiert anzeigen statt sie stillschweigend zu verwerfen.
            self._log(f"<{sender}> (unverschluesselt) {text}")
            return
        complete = self.reassembler.feed(text)
        if complete is None:
            return  # noch nicht alle Chunks da
        if self.cipher is None:
            return
        try:
            bundle = self.cipher.decrypt(complete)
        except Exception as e:
            self._log(f"<{sender}> [Entschluesselungsfehler: {e}]")
            return

        # Bundle-Format: "<zaehler>:<mac_hex>:<nachricht>"
        try:
            counter_str, mac, plaintext = bundle.split(":", 2)
            counter = int(counter_str)
        except ValueError:
            self._log(f"<{sender}> [ungueltiges Nachrichtenformat - verworfen]")
            return

        if not verify_mac(self.auth_key, counter, sender, plaintext, mac):
            self._log(f"⚠ <{sender}> [MAC ungueltig - Nachricht verworfen! "
                       f"Moeglich: falscher HMAC-Schluessel oder Manipulation]")
            return

        if not self.replay_guard.check_and_update(sender, counter):
            self._log(f"⚠ <{sender}> [Zaehler nicht neu - Replay verworfen]")
            return

        self._log(f"<{sender}> {plaintext}")
        if self.notify_var.get():
            self.root.bell()

    def _send(self):
        text = self.msg_var.get()
        if not text or not self.client:
            return

        if text.startswith("/"):
            self._send_command(text[1:])
            self.msg_var.set("")
            return

        if not self.cipher or not self.auth_key:
            return
        try:
            counter = new_counter()
            mac = compute_mac(self.auth_key, counter, self.my_nick, text)
            bundle = f"{counter}:{mac}:{text}"
            ciphertext = self.cipher.encrypt(bundle)
        except Exception as e:
            messagebox.showerror("Verschluesselungsfehler", str(e))
            return
        for frame in frame_message(ciphertext):
            self.client.send_privmsg(self.channel, frame)
        self._log(f"<ich> {text}")
        self.msg_var.set("")

    _MSG_ALIAS_RE = re.compile(r"^msg\s+(\S+)\s+(.+)$", re.IGNORECASE | re.DOTALL)

    def _send_command(self, command_text):
        """Sendet einen rohen IRC-Befehl (z.B. /join #anderer-channel,
        /nick neuernick, /part) UNVERSCHLUESSELT direkt ans Protokoll.
        Solche Befehle muss der Server selbst verstehen koennen - durch
        den Chiffre geschickt waeren sie fuer ihn nur Kauderwelsch, der
        Befehl wuerde schlicht ignoriert bzw. als Chat-Text missverstanden."""
        if not self.client:
            self._log("* Nicht verbunden.")
            return

        # /msg <ziel> <text> ist ein gaengiges IRC-Client-Kuerzel fuer
        # PRIVMSG <ziel> :<text> (kennt praktisch jeder IRC-Client,
        # z.B. auch Kiwi) - UnrealIRCd selbst kennt aber kein "MSG"-
        # Protokollkommando, daher hier vorher uebersetzen.
        match = self._MSG_ALIAS_RE.match(command_text)
        if match:
            target, message = match.group(1), match.group(2)
            command_text = f"PRIVMSG {target} :{message}"

        self.client.send_raw(command_text)
        self._log(f"* Befehl gesendet: /{command_text}")

        # Nach einem /join den aktiven Channel fuer verschluesselte
        # Nachrichten mitverfolgen, damit weitere Chat-Nachrichten an
        # den neuen Channel gehen.
        parts = command_text.split(None, 1)
        if parts and parts[0].lower() == "join" and len(parts) > 1:
            new_channel = parts[1].split(",")[0].split()[0]
            self.channel = new_channel
            self._joined = True
            self._log(f"* Aktiver Channel fuer verschluesselte Nachrichten: {self.channel}")

    def _on_close(self):
        if self.client:
            self.client.close()
        self.root.destroy()


def main():
    root = tk.Tk()
    ChatApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
