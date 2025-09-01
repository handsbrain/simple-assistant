import os, sys, base64, argparse, pathlib, requests

TENANT = os.getenv("MS_TENANT_ID", "")
CLIENT = os.getenv("MS_CLIENT_ID", "")
SECRET = os.getenv("MS_CLIENT_SECRET", "")
USER   = os.getenv("MS_USER_ID", "")

GRAPH  = "https://graph.microsoft.com/v1.0"
OUTDIR = pathlib.Path(os.getenv("ATTACH_PROBE_DIR", "attach_probe_out"))
OUTDIR.mkdir(parents=True, exist_ok=True)

S = requests.Session()
S.headers.update({"Accept":"application/json"})


def token() -> str:
    r = S.post(
        f"https://login.microsoftonline.com/{TENANT}/oauth2/v2.0/token",
        data={
            "client_id": CLIENT,
            "client_secret": SECRET,
            "scope": "https://graph.microsoft.com/.default",
            "grant_type": "client_credentials",
        },
        timeout=20,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def H(tok: str) -> dict:
    return {"Authorization": f"Bearer {tok}"}


def list_unread(tok: str, top: int = 5):
    r = S.get(
        f"{GRAPH}/users/{USER}/mailFolders/Inbox/messages",
        headers=H(tok),
        params={
            "$filter": "isRead eq false",
            "$orderby": "receivedDateTime desc",
            "$top": str(int(top)),
            "$select": "id,subject,receivedDateTime,conversationId,hasAttachments",
        },
        timeout=30,
    )
    r.raise_for_status()
    return r.json().get("value", [])


def list_attachments(tok: str, msg_id: str, top: int = 50):
    r = S.get(
        f"{GRAPH}/users/{USER}/messages/{msg_id}/attachments",
        headers=H(tok),
        params={"$top": str(int(top))},
        timeout=30,
    )
    r.raise_for_status()
    return r.json().get("value", [])


def fetch_attachment(tok: str, msg_id: str, att_id: str):
    # 1) Try metadata (may include contentBytes)
    r = S.get(
        f"{GRAPH}/users/{USER}/messages/{msg_id}/attachments/{att_id}",
        headers=H(tok),
        timeout=30,
    )
    r.raise_for_status()
    j = r.json() or {}
    name = j.get("name", "attachment")
    ctype = j.get("contentType", "")
    size = int(j.get("size") or 0)
    b64 = j.get("contentBytes") or ""
    data = base64.b64decode(b64) if b64 else b""
    source = "contentBytes"

    # 2) Fallback to raw stream via $value
    if (not data) and size > 0:
        rv = S.get(
            f"{GRAPH}/users/{USER}/messages/{msg_id}/attachments/{att_id}/$value",
            headers=H(tok),
            timeout=60,
            stream=True,
        )
        rv.raise_for_status()
        buf = bytearray()
        for chunk in rv.iter_content(65536):
            if not chunk:
                break
            buf.extend(chunk)
        data = bytes(buf)
        source = "$value"

    return name, ctype, size, source, data


def main():
    ap = argparse.ArgumentParser(description="Probe to download attachments from a mailbox message via Microsoft Graph")
    ap.add_argument("--message-id", help="Target message ID. If omitted, uses newest unread.")
    ap.add_argument("--scan-conv", action="store_true", help="If no attachments on that message, scan recent messages in the same conversation.")
    ap.add_argument("--top", type=int, default=5, help="Number of unread messages to inspect when message-id not supplied.")
    args = ap.parse_args()

    if not all([TENANT, CLIENT, SECRET, USER]):
        print("Missing env: MS_TENANT_ID, MS_CLIENT_ID, MS_CLIENT_SECRET, MS_USER_ID", file=sys.stderr)
        sys.exit(1)

    tok = token()

    msg_id = args.message_id
    conv_id = ""
    if not msg_id:
        msgs = list_unread(tok, top=args.top)
        if not msgs:
            print("No unread messages.")
            return
        msg = msgs[0]
        msg_id = msg["id"]
        conv_id = msg.get("conversationId", "")
        subj = msg.get("subject", "")
        print(f"Using newest unread: id={msg_id} conv={conv_id} subject={subj!r}")

    atts = list_attachments(tok, msg_id)
    if not atts and args.scan_convv:
        pass

    if not atts and args.scan_conv:
        # Retrieve conversationId and scan a few recent messages
        r = S.get(
            f"{GRAPH}/users/{USER}/messages/{msg_id}",
            headers=H(tok),
            params={"$select": "conversationId"},
            timeout=30,
        )
        r.raise_for_status()
        conv_id = (r.json() or {}).get("conversationId", "")
        if conv_id:
            r2 = S.get(
                f"{GRAPH}/users/{USER}/messages",
                headers=H(tok),
                params={
                    "$filter": f"conversationId eq '{conv_id}'",
                    "$orderby": "receivedDateTime desc",
                    "$top": "5",
                    "$select": "id,hasAttachments",
                },
                timeout=30,
            )
            r2.raise_for_status()
            for mm in r2.json().get("value", []):
                atts.extend(list_attachments(tok, mm["id"]))

    if not atts:
        print("No attachments found.")
        return

    print(f"Found {len(atts)} attachments")
    saved = 0
    for a in atts:
        otype = a.get("@odata.type", "")
        name = a.get("name", "attachment")
        if otype and "fileAttachment" not in otype:
            print(f"- skip non-file attachment: type={otype} name={name}")
            continue
        try:
            n, ctype, size, source, data = fetch_attachment(tok, msg_id, a["id"])
            out = OUTDIR / n
            out.write_bytes(data)
            print(f"- saved: {n} size={size}B type={ctype} via={source} -> {out}")
            saved += 1
        except Exception as e:
            print(f"- error fetching {name}: {type(e).__name__}: {e}")

    if saved == 0:
        print("No attachments were saved.")


if __name__ == "__main__":
    main()


