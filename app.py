# app.py
import os
from flask import Flask, request, jsonify, abort
from twilio.rest import Client
from datetime import datetime
import hmac, hashlib

app = Flask(__name__)

# Environment variables (heroku config vars)
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_WHATSAPP_FROM = os.environ.get("TWILIO_WHATSAPP_FROM")  # e.g. "whatsapp:+14155238886"
RECIPIENT_WHATSAPP = os.environ.get("RECIPIENT_WHATSAPP")      # e.g. "whatsapp:+9936XXXXXXX"
SHARED_SECRET = os.environ.get("RK_SHARED_SECRET", "")        # optional HMAC secret to validate webhook

if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_WHATSAPP_FROM and RECIPIENT_WHATSAPP):
    raise RuntimeError("Please set TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_WHATSAPP_FROM and RECIPIENT_WHATSAPP environment variables")

twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)

def verify_signature(raw_body: bytes, signature: str) -> bool:
    # Optional HMAC check (if R-Keeper can send a header with HMAC)
    if not SHARED_SECRET:
        return True
    if not signature:
        return False
    mac = hmac.new(SHARED_SECRET.encode(), msg=raw_body, digestmod=hashlib.sha256)
    expected = mac.hexdigest()
    return hmac.compare_digest(expected, signature)

@app.route("/rk", methods=["POST"])
def rk_webhook():
    raw = request.get_data()
    # optional header name X-RK-Signature (you must configure R-Keeper to send such header)
    signature = request.headers.get("X-RK-Signature", "")
    if not verify_signature(raw, signature):
        abort(401, "Invalid signature")

    try:
        payload = request.get_json(force=True)
    except Exception:
        abort(400, "Invalid JSON")

    # --- Adjust these fields according to actual R-Keeper payload ---
    # Try to read typical fields. If your payload differs, adjust mapping below.
    order_id = payload.get("order_id") or payload.get("id") or payload.get("OrderId") or "unknown"
    customer = payload.get("customer", {})
    customer_name = customer.get("name") or payload.get("client_name") or "Qonaq"
    items = payload.get("items") or payload.get("lines") or []
    total = payload.get("total") or payload.get("amount") or payload.get("sum") or "—"

    # Build items text
    items_text = ""
    if isinstance(items, list):
        for it in items:
            name = it.get("name") or it.get("product") or it.get("Title") or "item"
            qty = it.get("quantity") or it.get("qty") or it.get("count") or 1
            price = it.get("price") or it.get("unit_price") or ""
            items_text += f"- {name} x{qty} {price}\n"
    else:
        items_text = str(items)

    # Compose message
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    message_text = (
        f"Yeni sifariş!\n\n"
        f"Sifariş ID: {order_id}\n"
        f"Müştəri: {customer_name}\n\n"
        f"Əşyalar:\n{items_text}\n"
        f"Ümumi: {total}\n\n"
        f"Vaxt: {now}"
    )

    # Send WhatsApp via Twilio
    try:
        msg = twilio_client.messages.create(
            body=message_text,
            from_=TWILIO_WHATSAPP_FROM,
            to=RECIPIENT_WHATSAPP
        )
    except Exception as e:
        # Twilio error — return 500
        return jsonify({"ok": False, "error": str(e)}), 500

    return jsonify({"ok": True, "sid": msg.sid}), 200

@app.route("/", methods=["GET"])
def index():
    return "R-Keeper -> WhatsApp webhook running."

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
