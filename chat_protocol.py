"""
chat_protocol.py - Verpackt Ciphertext in IRC-taugliche Chunks (wegen der
512-Byte-Zeilenbegrenzung von IRC) und setzt sie beim Empfänger wieder
zusammen.

Frame-Format: CMSG:<msg_id>:<chunk_index>:<chunk_total>:<payload>
"""

import uuid

# Konservative Chunk-Größe (Zeichen). Lässt Puffer für IRC-Overhead
# (Befehl, Ziel-Channel, eigenes Hostmask beim Server, CRLF, ...).
MAX_PAYLOAD = 380


def frame_message(ciphertext):
    msg_id = uuid.uuid4().hex[:8]
    chunks = [ciphertext[i:i + MAX_PAYLOAD]
              for i in range(0, len(ciphertext), MAX_PAYLOAD)] or [""]
    total = len(chunks)
    return [f"CMSG:{msg_id}:{idx + 1}:{total}:{chunk}"
            for idx, chunk in enumerate(chunks)]


class Reassembler:
    """Setzt eingehende Chunks anhand ihrer msg_id wieder zusammen."""

    def __init__(self):
        self._pending = {}  # msg_id -> {"total": int, "parts": {idx: chunk}}

    def feed(self, line):
        """Nimmt eine empfangene IRC-Textzeile entgegen.
        Gibt den vollständigen Ciphertext zurück, sobald alle Chunks da
        sind - sonst None."""
        if not line.startswith("CMSG:"):
            return None
        try:
            _, msg_id, idx, total, chunk = line.split(":", 4)
            idx = int(idx)
            total = int(total)
        except ValueError:
            return None
        entry = self._pending.setdefault(msg_id, {"total": total, "parts": {}})
        entry["parts"][idx] = chunk
        if len(entry["parts"]) >= entry["total"]:
            del self._pending[msg_id]
            return "".join(entry["parts"][i] for i in range(1, total + 1))
        return None
