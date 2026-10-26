from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import uvicorn
import time

app = FastAPI(title="Nulltrace Relay Node", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SignedPost(BaseModel):
    public_key_hex: str
    display_name: str
    avatar: str
    bio: str
    message: str
    image: str | None = ""  # Gönderi görseli (Base64)
    reply_to: int | None = None
    signature_hex: str

class ActionPayload(BaseModel):
    public_key_hex: str
    post_id: int
    signature_hex: str

class DeletePayload(BaseModel):
    public_key_hex: str
    post_id: int
    signature_hex: str

FEED = []

@app.post("/api/post")
def create_post(post: SignedPost):
    if len(post.message.strip()) == 0 or len(post.message) > 280:
        raise HTTPException(status_code=400, detail="Gönderi 1-280 karakter olmalıdır.")
    if len(post.display_name.strip()) == 0 or len(post.display_name) > 30:
        raise HTTPException(status_code=400, detail="Kullanıcı adı geçersiz.")
    if post.image and len(post.image) > 1000000:  # ~700KB görsel boyutu sınırı
        raise HTTPException(status_code=400, detail="Gönderi görseli çok büyük.")

    try:
        reply_str = str(post.reply_to) if post.reply_to is not None else "None"
        image_str = post.image if post.image else ""
        payload_to_verify = f"{post.display_name}:{post.bio}:{post.avatar}:{post.message}:{image_str}:{reply_str}"
        verify_key = VerifyKey(bytes.fromhex(post.public_key_hex))
        verify_key.verify(payload_to_verify.encode('utf-8'), bytes.fromhex(post.signature_hex))
    except (BadSignatureError, ValueError) as e:
        raise HTTPException(status_code=401, detail=f"İmza geçersiz: {str(e)}")

    post_entry = {
        "id": len(FEED) + 1,
        "author_pubkey": post.public_key_hex,
        "display_name": post.display_name,
        "avatar": post.avatar,
        "bio": post.bio,
        "image": post.image,
        "short_author": f"{post.public_key_hex[:6]}...",
        "message": post.message,
        "reply_to": post.reply_to,
        "likes": [],
        "reposts": [],
        "timestamp": int(time.time())
    }

    FEED.insert(0, post_entry)
    return {"status": "success"}

@app.post("/api/like")
def like_post(action: ActionPayload):
    try:
        payload_to_verify = f"like:{action.post_id}"
        verify_key = VerifyKey(bytes.fromhex(action.public_key_hex))
        verify_key.verify(payload_to_verify.encode('utf-8'), bytes.fromhex(action.signature_hex))
    except (BadSignatureError, ValueError):
        raise HTTPException(status_code=401, detail="İmza geçersiz!")

    for post in FEED:
        if post["id"] == action.post_id:
            if action.public_key_hex in post["likes"]:
                post["likes"].remove(action.public_key_hex)
            else:
                post["likes"].append(action.public_key_hex)
            return {"status": "success", "likes_count": len(post["likes"])}

    raise HTTPException(status_code=404, detail="Gönderi bulunamadı.")

@app.post("/api/repost")
def repost_post(action: ActionPayload):
    try:
        payload_to_verify = f"repost:{action.post_id}"
        verify_key = VerifyKey(bytes.fromhex(action.public_key_hex))
        verify_key.verify(payload_to_verify.encode('utf-8'), bytes.fromhex(action.signature_hex))
    except (BadSignatureError, ValueError):
        raise HTTPException(status_code=401, detail="İmza geçersiz!")

    for post in FEED:
        if post["id"] == action.post_id:
            if action.public_key_hex in post["reposts"]:
                post["reposts"].remove(action.public_key_hex)
            else:
                post["reposts"].append(action.public_key_hex)
            return {"status": "success", "reposts_count": len(post["reposts"])}

    raise HTTPException(status_code=404, detail="Gönderi bulunamadı.")

@app.post("/api/delete")
def delete_post(action: DeletePayload):
    try:
        payload_to_verify = f"delete:{action.post_id}"
        verify_key = VerifyKey(bytes.fromhex(action.public_key_hex))
        verify_key.verify(payload_to_verify.encode('utf-8'), bytes.fromhex(action.signature_hex))
    except (BadSignatureError, ValueError):
        raise HTTPException(status_code=401, detail="İmza geçersiz!")

    global FEED
    target_post = next((p for p in FEED if p["id"] == action.post_id), None)
    
    if not target_post:
        raise HTTPException(status_code=404, detail="Gönderi bulunamadı.")
    
    if target_post["author_pubkey"] != action.public_key_hex:
        raise HTTPException(status_code=403, detail="Bu gönderiyi silme yetkin yok.")

    # Gönderiyi ve buna bağlı yanıtları akıştan çıkar
    FEED = [p for p in FEED if p["id"] != action.post_id and p.get("reply_to") != action.post_id]
    return {"status": "success"}

@app.get("/api/feed")
def get_feed():
    return {"feed": FEED}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, access_log=False)
