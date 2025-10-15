# tts_utils.py  <-- GANTIKAN file lama dengan ini
from gtts import gTTS
import uuid
import os
import platform

AUDIO_DIR = "audio"
os.makedirs(AUDIO_DIR, exist_ok=True)

def generate_mp3(text, lang='id'):
    """
    Generate tts mp3 synchronously, return filename (basename).
    Uses unique filename to avoid race condition.
    NOTE: for heavy load, offload to background worker (Celery/RQ).
    """
    try:
        filename = f"tts_{uuid.uuid4().hex}.mp3"
        filepath = os.path.join(AUDIO_DIR, filename)

        # gTTS already outputs mp3. Simpan langsung.
        tts = gTTS(text, lang=lang)
        tts.save(filepath)

        # Optional: return small-bitrate version only if needed.
        return filename
    except Exception as e:
        print(f"❌ Error saat generate_mp3: {e}")
        return None
