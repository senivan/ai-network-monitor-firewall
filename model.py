#!/usr/bin/env python3
import os
import time
import logging
from collections import deque
from typing import Dict, Any, List, Tuple

import numpy as np
import requests
import torch
import torch.nn as nn

API_BASE = os.environ.get("AI_FW_API", "http://127.0.0.1:8000")
EVENTS_URL = f"{API_BASE}/events"
VERDICTS_URL = f"{API_BASE}/ml/verdicts"

MODEL_PATH = os.environ.get("LSTM_AE_WEIGHTS", "weights.pt")
POLL_INTERVAL = float(os.environ.get("AI_FW_POLL_INTERVAL", "2.0"))
BATCH_LIMIT = int(os.environ.get("AI_FW_POLL_BATCH", "500"))

# Threshold по score (0..1), підібраний офлайн
ANOMALY_THRESHOLD = float(os.environ.get("AI_FW_THRESHOLD", "0.65"))

LOG_LEVEL = os.environ.get("AI_FW_LOG_LEVEL", "INFO").upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO))
log = logging.getLogger("ai_fw_worker")


class LSTMAE(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int = 64):
        super().__init__()
        self.encoder = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.decoder = nn.LSTM(hidden_dim, input_dim, batch_first=True)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z, _ = self.encoder(x)
        recon, _ = self.decoder(z)
        return recon


def load_lstm_model(path: str):
    # В чекпоінті лежать і sklearn-об’єкти, тому НЕ weights_only
    ckpt = torch.load(path, map_location="cpu", weights_only=False)

    input_dim = ckpt["input_dim"]
    window = ckpt["window"]
    stride = ckpt["stride"]
    scaler = ckpt["scaler"]
    encoders = ckpt["label_encoders"]

    state = ckpt["model_state"]
    w_ih = state["encoder.weight_ih_l0"]
    hidden_dim = w_ih.shape[0] // 4  # 4*hidden_dim x input_dim

    model = LSTMAE(input_dim=input_dim, hidden_dim=hidden_dim)
    model.load_state_dict(state)
    model.eval()

    log.info(
        "Loaded LSTM AE | input_dim=%d hidden_dim=%d window=%d stride=%d",
        input_dim, hidden_dim, window, stride
    )

    return model, window, stride, scaler, encoders


NUM_COLS = [
    "packet_len",
    "ip_ttl",
    "ip_tos",
    "src_port",
    "dst_port",
]

CAT_COLS = [
    "direction",
    "protocol",
    "ndpi_master_proto",
    "ndpi_app_proto",
    "ndpi_category",
    "dst_geo_country",
]


def _parse_timestamp(ts: Any) -> float:
    from datetime import datetime
    if isinstance(ts, (int, float)):
        return float(ts)
    if isinstance(ts, str):
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0.0
    return 0.0


def build_feature_vector(
    ev: Dict[str, Any],
    last_ts: float | None,
    scaler,
    encoders,
) -> Tuple[np.ndarray, float]:
    num = [
        ev.get("packet_len", 0.0),
        ev.get("ip_ttl", 0.0),
        ev.get("ip_tos", 0.0),
        ev.get("src_port", 0.0),
        ev.get("dst_port", 0.0),
    ]

    cat: List[float] = []
    for col in CAT_COLS:
        le = encoders[col]
        raw = str(ev.get(col, "UNKNOWN"))
        if raw in le.classes_:
            cat.append(le.transform([raw])[0])
        else:
            # unseen category → мапимо в 0 (часто це якийсь базовий клас)
            cat.append(0)

    # time_delta так само як у ноутбуці
    ts = _parse_timestamp(ev.get("timestamp"))
    delta = 0.0 if last_ts is None else max(0.0, ts - last_ts)

    x = np.array([num + cat + [delta]], dtype=np.float32)
    x_scaled = scaler.transform(x)

    return x_scaled[0], ts


class StreamingScorer:
    def __init__(self, model, window, stride, scaler, encoders):
        self.model = model
        self.window = window
        self.stride = stride
        self.scaler = scaler
        self.encoders = encoders

        self.history: deque[np.ndarray] = deque(maxlen=window * 3)
        self.last_ts: float | None = None

      self.ema_mean: float | None = None
        self.ema_var: float | None = None
        self.alpha: float = 0.02
        self.min_seq = window

    def _update_ema_stats(self, mse: float) -> None:
        if self.ema_mean is None:
            self.ema_mean = mse
            self.ema_var = 0.0
            return

        diff = mse - self.ema_mean
        self.ema_mean += self.alpha * diff

        if self.ema_var is None:
            self.ema_var = diff * diff
        else:
            self.ema_var = (1 - self.alpha) * (self.ema_var + self.alpha * diff * diff)

    def _mse_to_score(self, mse: float) -> float:
        """
        Перетворюємо MSE → score ∈ [0,1] через z-score + sigmoid.
        Для нормального трафіку z ≈ 0 → score ≈ 0.5,
        великі аномалії → score → 1, дуже маленькі помилки → score → 0.
        """
        if self.ema_mean is None or self.ema_var is None:
            return 0.0

        std = float(np.sqrt(max(self.ema_var, 1e-8)))
        z = (mse - self.ema_mean) / (std + 1e-8)
        z_scaled = z / 3.0  # очікуємо, що "нормальний" z лежить ~[-3,3]

        score = 1.0 / (1.0 + float(np.exp(-z_scaled)))
        return float(np.clip(score, 0.0, 1.0))

    def add_event(self, ev: Dict[str, Any]) -> Tuple[float | None, float | None]:
        """
        Подаємо один івент. Коли є достатньо історії, повертаємо (mse, score).
        Інакше (None, None).
        """
        feats, ts = build_feature_vector(
            ev, self.last_ts, self.scaler, self.encoders
        )
        self.last_ts = ts

        self.history.append(feats)

        if len(self.history) < self.min_seq:
            return None, None
        seq = np.array(self.history)[-self.window:]
        x = torch.tensor(seq[None, ...], dtype=torch.float32)

        with torch.no_grad():
            recon = self.model(x)
            mse = torch.mean((recon - x) ** 2).item()
        self._update_ema_stats(mse)
        score = self._mse_to_score(mse)
        return mse, score

sess = requests.Session()


def fetch_new_events(last_seen_id: int) -> List[Dict[str, Any]]:
    params = {"limit": BATCH_LIMIT}
    try:
        r = sess.get(EVENTS_URL, params=params, timeout=5)
        r.raise_for_status()
        data = r.json()

        if not isinstance(data, list):
            log.warning("Unexpected /events payload: %r", data)
            return []

        evs = [e for e in data if int(e.get("id", 0)) > last_seen_id]
        evs.sort(key=lambda e: int(e["id"]))
        return evs

    except Exception as e:
        log.error("Failed to fetch events: %s", e)
        return []


def send_verdict(event_id: int, raw_error: float, score: float) -> None:
    """
    Відправляємо на API в форматі MlVerdict:
      event_id: int
      model: str
      raw_error: float (MSE)
      score: float [0,1]
      label: "normal" | "anomaly"
    """
    payload = {
        "event_id": event_id,
        "model": "lstm_ae",
        "raw_error": raw_error,
        "score": score,
        "label": "anomaly" if score >= ANOMALY_THRESHOLD else "normal",
    }

    try:
        r = sess.post(VERDICTS_URL, json=payload, timeout=5)
        if r.status_code >= 300:
            log.warning(
                "POST /ml/verdicts %s %s",
                r.status_code,
                r.text[:200],
            )
    except Exception as e:
        log.error("Failed to send verdict: %s", e)


def main():
    if not os.path.exists(MODEL_PATH):
        raise SystemExit(f"Model not found: {MODEL_PATH}")

    model, window, stride, scaler, encoders = load_lstm_model(MODEL_PATH)

    scorer = StreamingScorer(
        model=model,
        window=window,
        stride=stride,
        scaler=scaler,
        encoders=encoders,
    )

    last_seen_id = 0
    log.info("Worker started | polling %s", EVENTS_URL)

    while True:
        try:
            events = fetch_new_events(last_seen_id)

            for ev in events:
                eid = int(ev["id"])
                last_seen_id = max(last_seen_id, eid)

                mse, score = scorer.add_event(ev)
                if mse is None or score is None:
                    continue  # ще розігріваємось

                if score >= ANOMALY_THRESHOLD:
                    log.warning("ANOMALY id=%d mse=%.6f score=%.3f", eid, mse, score)
                else:
                    log.debug("normal id=%d mse=%.6f score=%.3f", eid, mse, score)

                send_verdict(eid, mse, score)

        except KeyboardInterrupt:
            log.info("Stopping worker")
            break
        except Exception as e:
            log.exception("Worker error: %s", e)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
