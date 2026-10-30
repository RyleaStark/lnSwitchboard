"""Scoped private clients and durable idempotency on the existing private database."""
from __future__ import annotations

import hashlib
import json
import secrets
import time
from pathlib import Path
from uuid import uuid4

from fastapi import HTTPException

from .connection_secret_store import ConnectionSecretStore
from .sqlite_utils import sqlite_connection


def digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ClientStore:
    def __init__(self, path: Path, secret_store: ConnectionSecretStore):
        self.path = path
        self.secrets = secret_store
        with sqlite_connection(path) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS api_clients (
                    id TEXT PRIMARY KEY, key_hash TEXT UNIQUE NOT NULL,
                    domain TEXT NOT NULL, scopes TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS api_owned_addresses (
                    id TEXT PRIMARY KEY, client_id TEXT NOT NULL, user_ref_hash TEXT NOT NULL,
                    local_part TEXT NOT NULL, domain TEXT NOT NULL,
                    UNIQUE(client_id, user_ref_hash)
                );
                CREATE TABLE IF NOT EXISTS api_client_requests (
                    id TEXT PRIMARY KEY, client_id TEXT NOT NULL, key_hash TEXT NOT NULL,
                    fingerprint TEXT NOT NULL, kind TEXT NOT NULL, logical_id TEXT NOT NULL,
                    resource_id TEXT NOT NULL, payment_hash TEXT,
                    lease_owner TEXT, lease_until INTEGER NOT NULL DEFAULT 0, result TEXT,
                    UNIQUE(client_id, key_hash), UNIQUE(client_id, kind, logical_id)
                );
            """)

    def provision(self, *, domain: str, scopes: list[str], webhook_url: str, webhook_secret: str) -> dict:
        client_id = str(uuid4())
        token = "lnsc_" + secrets.token_urlsafe(32)
        self.secrets.set(f"api-client:{client_id}", {
            "webhook_url": webhook_url, "webhook_secret": webhook_secret,
        })
        with sqlite_connection(self.path) as db:
            db.execute("INSERT INTO api_clients (id,key_hash,domain,scopes) VALUES (?,?,?,?)",
                       (client_id, digest(token), domain, json.dumps(scopes)))
        return {"client_id": client_id, "token": token, "domain": domain, "scopes": scopes}

    def authenticate(self, token: str, scope: str) -> dict:
        with sqlite_connection(self.path) as db:
            row = db.execute("SELECT * FROM api_clients WHERE key_hash=? AND revoked=0",
                             (digest(token),)).fetchone()
        if row is None:
            raise HTTPException(401, "Invalid client credentials", headers={"WWW-Authenticate": "Bearer"})
        client = dict(row)
        if scope not in json.loads(client["scopes"]):
            raise HTTPException(403, "Client scope required")
        return client

    def require_active(self, client_id: str) -> None:
        with sqlite_connection(self.path) as db:
            row = db.execute("SELECT revoked FROM api_clients WHERE id=?", (client_id,)).fetchone()
        if row is None or row["revoked"]:
            raise HTTPException(401, "Client credential revoked")

    def list_clients(self) -> list[dict]:
        with sqlite_connection(self.path) as db:
            return [{"client_id": r["id"], "domain": r["domain"],
                     "scopes": json.loads(r["scopes"]), "revoked": bool(r["revoked"])}
                    for r in db.execute("SELECT id,domain,scopes,revoked FROM api_clients ORDER BY id")]

    def revoke(self, client_id: str) -> None:
        with sqlite_connection(self.path) as db:
            if not db.execute("UPDATE api_clients SET revoked=1 WHERE id=?", (client_id,)).rowcount:
                raise HTTPException(404, "Not Found")

    def own_address(self, client_id: str, address_id: str) -> dict:
        with sqlite_connection(self.path) as db:
            row = db.execute("SELECT * FROM api_owned_addresses WHERE client_id=? AND id=?",
                             (client_id, address_id)).fetchone()
        if row is None:
            raise HTTPException(404, "Not Found")
        return dict(row)

    def reserve_address(self, client: dict, user_ref: str, resource_id: str) -> dict:
        ref = digest(user_ref)
        with sqlite_connection(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM api_owned_addresses WHERE client_id=? AND user_ref_hash=?",
                             (client["id"], ref)).fetchone()
            if row is None:
                address_id = resource_id
                local_part = "pay-" + secrets.token_hex(16)
                db.execute("INSERT INTO api_owned_addresses VALUES (?,?,?,?,?)",
                           (address_id, client["id"], ref, local_part, client["domain"]))
                row = db.execute("SELECT * FROM api_owned_addresses WHERE id=?", (address_id,)).fetchone()
            return dict(row)

    def claim(self, client_id: str, key: str, kind: str, body: dict, logical_id: str,
              *, resource_id: str, invoice: bool = False) -> dict:
        with sqlite_connection(self.path) as db:
            existing = db.execute("SELECT id FROM api_client_requests WHERE client_id=? AND key_hash=?",
                                  (client_id, digest(key))).fetchone()
        self.require_active(client_id)
        request_id = str(uuid4())
        preimage = secrets.token_bytes(32) if invoice and existing is None else None
        if preimage is not None:
            self.secrets.set(f"api-invoice:{request_id}", {"preimage": preimage.hex()})
        try:
            return self._claim_prepared(client_id, key, kind, body, logical_id,
                                        resource_id, request_id, preimage)
        finally:
            if preimage is not None:
                with sqlite_connection(self.path) as db:
                    used = db.execute("SELECT 1 FROM api_client_requests WHERE id=?", (request_id,)).fetchone()
                if used is None:
                    self.secrets.delete(f"api-invoice:{request_id}")

    def _claim_prepared(self, client_id, key, kind, body, logical_id, resource_id, request_id, preimage):
        fingerprint = digest(json.dumps({"kind": kind, "body": body}, sort_keys=True, separators=(",", ":")))
        owner = secrets.token_hex(16)
        now = int(time.time())
        with sqlite_connection(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM api_client_requests WHERE client_id=? AND key_hash=?",
                             (client_id, digest(key))).fetchone()
            if row is None:
                duplicate = db.execute(
                    "SELECT id FROM api_client_requests WHERE client_id=? AND kind=? AND logical_id=?",
                    (client_id, kind, logical_id),
                ).fetchone()
                if duplicate:
                    raise HTTPException(409, "Resource already has an idempotent request")
                db.execute("""INSERT INTO api_client_requests
                    (id,client_id,key_hash,fingerprint,kind,logical_id,resource_id,payment_hash)
                    VALUES (?,?,?,?,?,?,?,?)""", (request_id, client_id, digest(key), fingerprint,
                    kind, logical_id, resource_id, hashlib.sha256(preimage).hexdigest() if preimage else None))
                row = db.execute("SELECT * FROM api_client_requests WHERE id=?", (request_id,)).fetchone()
            if row["fingerprint"] != fingerprint:
                raise HTTPException(409, "Idempotency key conflicts with request")
            if row["result"] is not None:
                return dict(row)
            if row["lease_until"] > now:
                raise HTTPException(409, "Request is in progress", headers={"Retry-After": "2"})
            db.execute("UPDATE api_client_requests SET lease_owner=?,lease_until=? WHERE id=?",
                       (owner, now + 90, row["id"]))
            result = dict(row)
            result["lease_owner"] = owner
            return result

    def confirm_invoice(self, payment_hash: str, payment_request: str, expires_at: str) -> None:
        with sqlite_connection(self.path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT details FROM invoice_events WHERE payment_hash=?", (payment_hash,)).fetchone()
            if row is None:
                raise HTTPException(503, "Invoice tracking unavailable")
            details = json.loads(row["details"])
            details["client_invoice"]["creation_pending"] = False
            db.execute("""UPDATE invoice_events SET details=?,payment_request=?,expires_at=?,
                expired=CASE WHEN settled=1 THEN expired ELSE 0 END
                WHERE payment_hash=?""", (json.dumps(details), payment_request, expires_at, payment_hash))

    def finish(self, request: dict, result: dict) -> None:
        with sqlite_connection(self.path) as db:
            changed = db.execute("""UPDATE api_client_requests SET result=?,lease_owner=NULL,lease_until=0
                WHERE id=? AND lease_owner=?""", (json.dumps(result), request["id"], request["lease_owner"]))
            if not changed.rowcount:
                raise HTTPException(409, "Request lease changed; retry")

    def release(self, request: dict) -> None:
        with sqlite_connection(self.path) as db:
            db.execute("""UPDATE api_client_requests SET lease_owner=NULL,lease_until=0
                WHERE id=? AND lease_owner=?""", (request["id"], request.get("lease_owner")))
