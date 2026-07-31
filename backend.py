# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 BOBI SAS, France
# Auteur : Cyril Mazouer, pour le compte de BOBI SAS
# Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.

"""
Coffre à identifiants — backend in-process.

Modèle à deux étages, parce qu'une même machine a rarement UN seul accès :

    coffre (partagé)  →  équipement (nom, adresse, catégorie…)  →  accès (n par équipement)

L'ÉQUIPEMENT porte l'identité (la caméra, le serveur, l'interface) ; l'ACCÈS porte le
couple login/mot de passe ET sa nature : interface web, SSH/CLI, SNMP, console série…
Une caméra peut ainsi avoir « admin (web) », « root (SSH) » et « communauté SNMP » sans
qu'on invente trois machines.

Le PARTAGE se règle au niveau du coffre, jamais de l'entrée : on partage « Régie A » en
lecture à un groupe, pas quarante mots de passe un par un.

    Chiffrement — les mots de passe sont chiffrés au repos (AES-256-GCM). La clé maître
    vit HORS de la base : fichier `coffre.key` à côté du .db (0600), ou réglage
    `VAULT_KEY` dans config_local.py. Conséquence à connaître : une sauvegarde de la
    base SEULE ne suffit pas à restaurer les secrets — il faut aussi la clé. L'UI le
    rappelle et permet de la copier ailleurs.

    Ce que le chiffrement protège : un .db qui fuite (sauvegarde égarée, disque sorti,
    zip de distribution). Ce qu'il NE protège pas : quelqu'un qui a déjà la machine ET
    la clé. Le contrôle d'accès applicatif, lui, protège entre utilisateurs.

Un secret ne sort JAMAIS d'une liste : `devices` renvoie des accès sans mot de passe.
Le révéler est un appel explicite (`reveal`), journalisé nominativement dans l'audit.

Contrat : def api(path, method, payload, ctx) -> data | (status, data) | flask.Response

  GET    meta                                  -> référentiels + droits + état de la clé
  GET    directory                             -> utilisateurs / groupes / rôles (partage)
  GET    vaults                                -> coffres visibles (+ niveau de l'appelant)
  POST   vaults        {name, desc}            -> { id }
  PUT    vaults/<id>   {name?, desc?, share?}  -> { ok }
  DELETE vaults/<id>                           -> { ok }   (coffre vide uniquement)
  GET    devices       ?vault=&q=              -> équipements + accès SANS secret
  POST   devices       {vault_id, name, …}     -> { id }
  PUT    devices/<id>  {…}                     -> { ok }
  DELETE devices/<id>                          -> { ok }
  GET    reveal        ?device_id=&account_id=&index=   -> { secret }   (audité)
  GET    history       ?device_id=&account_id=          -> rotations (sans secrets)
  GET    generate      ?length=&symbols=                -> { password }
  GET    export        ?vault=<id>                      -> CSV en clair (audité, admin)
  POST   import        {vault_id, csv}                  -> { created, errors }
"""
import base64
import binascii
import csv
import io
import json
import os
import re
import secrets
import string
from datetime import datetime, timedelta

from flask import Response

# ─── Chiffrement ────────────────────────────────────────────
# Import protégé : sans la lib, l'outil doit refuser proprement (message actionnable)
# plutôt que disparaître du lanceur — un plugin dont le backend lève à l'import est
# chargé « front-pur » et l'utilisateur ne comprend pas pourquoi rien ne répond.
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_OK = True
except Exception:                                        # pragma: no cover
    AESGCM = None
    CRYPTO_OK = False

KEY_FILENAME = "coffre.key"
_ENC_PREFIX = "v1:"          # marqueur de format, pour pouvoir tourner de clé un jour
_key_cache = None


def _key_path():
    """La clé vit À CÔTÉ de la base, jamais dans le dossier du plugin : `plugins/coffre/`
    est écrasé à chaque mise à jour ou changement de version, la clé y serait perdue."""
    from app.config import DB_PATH
    return os.path.join(os.path.dirname(os.path.abspath(DB_PATH)), KEY_FILENAME)


def _load_key():
    """Clé maître 32 octets. Priorité à `VAULT_KEY` (config_local.py) ; sinon fichier
    `coffre.key`, créé au premier usage avec des droits restreints."""
    global _key_cache
    if _key_cache is not None:
        return _key_cache
    try:
        from app import config
        raw = getattr(config, "VAULT_KEY", None)
    except Exception:
        raw = None
    if raw:
        key = _decode_key(raw)
        if key:
            _key_cache = key
            return key
    path = _key_path()
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8") as f:
            key = _decode_key(f.read().strip())
        if key:
            _key_cache = key
            return key
        raise ValueError(f"{path} illisible (clé attendue : 32 octets en base64)")
    key = secrets.token_bytes(32)
    # 0600 posé AVANT l'écriture : la clé ne doit jamais exister, même une fraction de
    # seconde, avec les droits par défaut du processus.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(base64.b64encode(key).decode())
    _key_cache = key
    return key


def _decode_key(raw):
    raw = (raw or "").strip()
    for dec in (base64.b64decode, bytes.fromhex):
        try:
            k = dec(raw)
            if len(k) == 32:
                return k
        except (binascii.Error, ValueError):
            continue
    return None


def encrypt(plain):
    """Chiffre un secret. Une valeur vide reste vide (pas de blob pour « rien »)."""
    if plain is None or plain == "":
        return ""
    nonce = secrets.token_bytes(12)
    blob = nonce + AESGCM(_load_key()).encrypt(nonce, plain.encode("utf-8"), b"coffre")
    return _ENC_PREFIX + base64.b64encode(blob).decode()


def decrypt(blob):
    """Déchiffre. Renvoie None si le contenu est illisible avec la clé courante — cas
    typique d'une base restaurée sans sa clé : on le dit, on ne l'affiche pas en vide."""
    if not blob:
        return ""
    if not blob.startswith(_ENC_PREFIX):
        return blob            # entrée importée en clair, pas encore rechiffrée
    try:
        data = base64.b64decode(blob[len(_ENC_PREFIX):])
        return AESGCM(_load_key()).decrypt(data[:12], data[12:], b"coffre").decode("utf-8")
    except Exception:
        return None


def key_state():
    """Renseigne l'UI sans jamais exposer la clé : présence, origine, empreinte courte
    (pour vérifier d'un coup d'œil que deux instances portent bien la même)."""
    if not CRYPTO_OK:
        return {"ok": False, "reason": "lib_missing"}
    try:
        from app import config
        source = "config_local" if getattr(config, "VAULT_KEY", None) else "file"
        key = _load_key()
    except Exception as e:
        return {"ok": False, "reason": str(e)}
    import hashlib
    return {"ok": True, "source": source, "path": _key_path() if source == "file" else "",
            "fingerprint": hashlib.sha256(key).hexdigest()[:12]}


# ─── Référentiels ───────────────────────────────────────────
# Le type d'accès est la réponse au « parfois CLI, parfois web » : c'est l'accès qui le
# porte, pas la machine.
ACCESS_KINDS = [
    {"id": "web",    "label": "Interface web",   "scheme": "https", "port": 443},
    {"id": "ssh",    "label": "SSH / CLI",       "scheme": "ssh",   "port": 22},
    {"id": "telnet", "label": "Telnet",          "scheme": "telnet", "port": 23},
    {"id": "ftp",    "label": "FTP / SFTP",      "scheme": "ftp",   "port": 21},
    {"id": "rdp",    "label": "Bureau à distance", "scheme": "rdp", "port": 3389},
    {"id": "vnc",    "label": "VNC",             "scheme": "vnc",   "port": 5900},
    {"id": "snmp",   "label": "SNMP",            "scheme": "",      "port": 161},
    {"id": "api",    "label": "API / REST",      "scheme": "https", "port": 443},
    {"id": "serial", "label": "Console série",   "scheme": "",      "port": 0},
    {"id": "panel",  "label": "Façade / OSD",    "scheme": "",      "port": 0},
    {"id": "db",     "label": "Base de données", "scheme": "",      "port": 0},
    {"id": "os",     "label": "Session système", "scheme": "",      "port": 0},
    {"id": "other",  "label": "Autre",           "scheme": "",      "port": 0},
]
KIND_IDS = {k["id"] for k in ACCESS_KINDS}

CATEGORIES = [
    {"id": "ordinateur",  "label": "Ordinateur"},
    {"id": "camera",      "label": "Caméra"},
    {"id": "interface",   "label": "Interface / convertisseur"},
    {"id": "switch",      "label": "Switch / routeur"},
    {"id": "serveur",     "label": "Serveur"},
    {"id": "enregistreur", "label": "Enregistreur"},
    {"id": "melangeur",   "label": "Mélangeur / régie"},
    {"id": "audio",       "label": "Audio"},
    {"id": "stockage",    "label": "Stockage"},
    {"id": "onduleur",    "label": "Onduleur / PDU"},
    {"id": "autre",       "label": "Autre"},
]
CATEGORY_IDS = {c["id"] for c in CATEGORIES}

LEVELS = ("read", "write")
SCOPE_VAULT = "vault"
SCOPE_DEVICE = "device"

DEFAULT_ROTATE_DAYS = 365
DEFAULT_HISTORY_LEN = 10
MAX_HISTORY_LEN = 50


def _now():
    return datetime.now().isoformat(timespec="seconds")


def _s(v, maxlen=200):
    return str(v if v is not None else "").strip()[:maxlen]


# ─── Accès au store (typé, borné au plugin) ─────────────────

def _rows(ctx, scope):
    return ctx.store.list(scope)


def _row(ctx, scope, sid):
    """Lit une entrée EN VÉRIFIANT type et scope : `store.get` interroge la table
    commune à tous les outils, un id étranger renverrait sinon la donnée d'un autre
    plugin."""
    try:
        r = ctx.store.get(int(sid))
    except (TypeError, ValueError):
        return None
    if not r or r.get("type") != "coffre" or r.get("scope") != scope:
        return None
    return r


# ─── Partage et droits ──────────────────────────────────────

def _empty_share():
    return {"users": [], "groups": [], "roles": []}


def _clean_share(share):
    """Normalise une politique de partage venue du front : listes d'entrées
    {id, level}, niveaux bornés, doublons écrasés par le plus permissif."""
    out = _empty_share()
    if not isinstance(share, dict):
        return out
    for kind in ("users", "groups", "roles"):
        seen = {}
        for ent in (share.get(kind) or []):
            if not isinstance(ent, dict):
                continue
            ident = ent.get("id")
            if kind == "roles":
                ident = _s(ident, 40)
                if ident not in ("admin", "operator", "viewer"):
                    continue
            else:
                try:
                    ident = int(ident)
                except (TypeError, ValueError):
                    continue
            level = ent.get("level") if ent.get("level") in LEVELS else "read"
            # « write » l'emporte si la même cible apparaît deux fois.
            if seen.get(ident) != "write":
                seen[ident] = level
        out[kind] = [{"id": k, "level": v} for k, v in seen.items()]
    return out


def _level_for(vault_value, ctx):
    """Niveau de l'appelant sur un coffre : None | 'read' | 'write' | 'admin'.

    'admin' = propriétaire du coffre, ou administrateur de l'application. Un admin voit
    tout : il détient de toute façon la base ET la clé — le prétendre aveugle serait un
    faux-semblant. Ses lectures sont journalisées comme les autres."""
    u = ctx.user or {}
    uid, role = u.get("id"), u.get("role")
    if not uid:
        return None
    if role == "admin" or vault_value.get("owner_id") == uid:
        return "admin"
    share = vault_value.get("share") or _empty_share()
    best = None
    my_groups = set(ctx.my_groups())
    for ent in (share.get("users") or []):
        if ent.get("id") == uid:
            best = _max_level(best, ent.get("level"))
    for ent in (share.get("groups") or []):
        if ent.get("id") in my_groups:
            best = _max_level(best, ent.get("level"))
    for ent in (share.get("roles") or []):
        if ent.get("id") == role:
            best = _max_level(best, ent.get("level"))
    return best


def _max_level(a, b):
    order = {None: 0, "read": 1, "write": 2, "admin": 3}
    return a if order.get(a, 0) >= order.get(b, 0) else b


def _visible_vaults(ctx):
    """[(row, level)] des coffres accessibles à l'appelant, triés par nom."""
    out = []
    for r in _rows(ctx, SCOPE_VAULT):
        lvl = _level_for(r["value"], ctx)
        if lvl:
            out.append((r, lvl))
    return out


def _vault_for(ctx, vault_id, need="read"):
    """Charge un coffre et vérifie le niveau requis. Renvoie (row, level) ou (None, err)."""
    r = _row(ctx, SCOPE_VAULT, vault_id)
    if not r:
        return None, (404, {"error": "coffre introuvable"})
    lvl = _level_for(r["value"], ctx)
    order = {"read": 1, "write": 2, "admin": 3}
    if not lvl or order[lvl] < order[need]:
        # 404 et non 403 quand rien n'est visible : inutile de confirmer l'existence
        # d'un coffre à quelqu'un qui n'y a pas droit.
        return None, ((404, {"error": "coffre introuvable"}) if not lvl
                      else (403, {"error": "droits insuffisants sur ce coffre"}))
    return (r, lvl), None


# ─── Équipements et accès ───────────────────────────────────

def _new_account_id():
    return secrets.token_hex(4)


def _public_account(acc, rotate_days):
    """Vue publique d'un accès : tout sauf le secret. `has_secret` dit qu'il y en a un,
    `stale` qu'il mériterait d'être changé, `unreadable` qu'il est chiffré avec une
    autre clé (base restaurée sans sa clé)."""
    blob = acc.get("secret") or ""
    out = {
        "id": acc.get("id"), "kind": acc.get("kind") or "other",
        "label": acc.get("label") or "", "login": acc.get("login") or "",
        "port": acc.get("port") or "", "url": acc.get("url") or "",
        "notes": acc.get("notes") or "",
        "updated_at": acc.get("updated_at") or "", "updated_by": acc.get("updated_by") or "",
        "has_secret": bool(blob), "history_count": len(acc.get("history") or []),
    }
    out["unreadable"] = bool(blob) and decrypt(blob) is None
    out["stale"] = _is_stale(acc.get("updated_at"), rotate_days)
    return out


def _is_stale(updated_at, rotate_days):
    if not rotate_days or not updated_at:
        return False
    try:
        return datetime.fromisoformat(updated_at) < datetime.now() - timedelta(days=int(rotate_days))
    except ValueError:
        return False


def _merge_accounts(old_accounts, new_accounts, ctx, history_len):
    """Fusionne les accès envoyés par le front avec ceux en base.

    ATTENTION — la liste reçue REMPLACE la liste enregistrée : un accès existant absent
    de l'envoi est supprimé (avec son historique). L'écran d'édition renvoie toujours la
    liste complète ; un appel d'API qui n'enverrait qu'un accès effacerait les autres.
    Ces retraits sont journalisés, pour qu'une disparition reste explicable après coup.

    Règle du secret, pensée pour que l'UI n'ait jamais à renvoyer un mot de passe qu'elle
    ne connaît pas : champ ABSENT ou None → inchangé ; chaîne non vide → nouveau secret
    (l'ancien bascule dans l'historique) ; chaîne vide → secret effacé."""
    by_id = {a.get("id"): a for a in (old_accounts or [])}
    who = (ctx.user or {}).get("username") or "?"
    out = []
    for inc in (new_accounts or []):
        if not isinstance(inc, dict):
            continue
        prev = by_id.get(inc.get("id")) or {}
        acc = {
            "id": prev.get("id") or _new_account_id(),
            "kind": inc.get("kind") if inc.get("kind") in KIND_IDS else (prev.get("kind") or "other"),
            "label": _s(inc.get("label"), 120),
            "login": _s(inc.get("login"), 200),
            "port": _s(inc.get("port"), 20),
            "url": _s(inc.get("url"), 400),
            "notes": _s(inc.get("notes"), 2000),
            "secret": prev.get("secret") or "",
            "history": list(prev.get("history") or []),
            "updated_at": prev.get("updated_at") or "",
            "updated_by": prev.get("updated_by") or "",
        }
        raw = inc.get("secret")
        if raw is not None:
            new_secret = encrypt(raw) if raw != "" else ""
            if new_secret != acc["secret"]:
                if acc["secret"] and history_len:
                    acc["history"].insert(0, {"secret": acc["secret"],
                                              "replaced_at": _now(), "by": who})
                    del acc["history"][history_len:]
                acc["secret"] = new_secret
                acc["updated_at"] = _now()
                acc["updated_by"] = who
        out.append(acc)
    dropped = [a for a in (old_accounts or [])
               if a.get("id") not in {x["id"] for x in out}]
    for a in dropped:
        ctx.audit("account_delete",
                  f"accès {a.get('kind')} « {a.get('login') or '—'} » supprimé "
                  f"({len(a.get('history') or [])} rotation(s) perdue(s))")
    return out


def _device_public(row, rotate_days):
    v = row["value"]
    return {
        "id": row["id"], "name": row["name"], "vault_id": v.get("vault_id"),
        "address": v.get("address") or "", "category": v.get("category") or "autre",
        "vendor": v.get("vendor") or "", "model": v.get("model") or "",
        "site": v.get("site") or "", "tags": v.get("tags") or [],
        "notes": v.get("notes") or "", "updated_at": row.get("updated_at"),
        "accounts": [_public_account(a, rotate_days) for a in (v.get("accounts") or [])],
    }


def _device_matches(dev, q):
    """Recherche plein texte — sur tout SAUF les secrets (un mot de passe ne doit pas
    pouvoir être deviné en observant quels termes de recherche « répondent »)."""
    if not q:
        return True
    hay = " ".join([dev["name"], dev["address"], dev["vendor"], dev["model"], dev["site"],
                    dev["notes"], " ".join(dev["tags"]),
                    " ".join(a["login"] + " " + a["label"] + " " + a["kind"]
                             for a in dev["accounts"])]).lower()
    return all(term in hay for term in q.lower().split())


def _settings(ctx):
    def _num(key, default, lo, hi):
        try:
            return max(lo, min(hi, int(float(ctx.setting(key, default)))))
        except (TypeError, ValueError):
            return default
    return (_num("rotate_days", DEFAULT_ROTATE_DAYS, 0, 3650),
            _num("history_len", DEFAULT_HISTORY_LEN, 0, MAX_HISTORY_LEN))


# ─── Routeur ────────────────────────────────────────────────

def api(path, method, payload, ctx):
    path = (path or "").strip("/")
    payload = payload if isinstance(payload, dict) else {}
    if not CRYPTO_OK:
        return 503, {"error": "module de chiffrement absent — installer « cryptography » "
                              "dans le venv (./venv/bin/python -m pip install cryptography)"}
    parts = path.split("/")
    head = parts[0] if parts else ""
    rotate_days, history_len = _settings(ctx)

    # ── Référentiels et annuaire ──
    if head == "meta" and method == "GET":
        u = ctx.user or {}
        return {"kinds": ACCESS_KINDS, "categories": CATEGORIES,
                "levels": list(LEVELS), "rotate_days": rotate_days,
                "key": key_state(),
                "me": {"id": u.get("id"), "username": u.get("username"),
                       "role": u.get("role"), "can_write": ctx.has_perm("tools.use")}}

    if head == "directory" and method == "GET":
        return {"users": ctx.users(), "groups": ctx.groups(),
                "roles": [{"id": "admin", "label": "Administrateurs"},
                          {"id": "operator", "label": "Opérateurs"},
                          {"id": "viewer", "label": "Lecteurs"}]}

    # ── Coffres ──
    if head == "vaults":
        if method == "GET" and len(parts) == 1:
            counts = {}
            for d in _rows(ctx, SCOPE_DEVICE):
                vid = d["value"].get("vault_id")
                counts[vid] = counts.get(vid, 0) + 1
            users = {u["id"]: u["username"] for u in ctx.users()}
            out = []
            for r, lvl in _visible_vaults(ctx):
                v = r["value"]
                out.append({"id": r["id"], "name": r["name"], "desc": v.get("desc") or "",
                            "owner_id": v.get("owner_id"),
                            "owner": users.get(v.get("owner_id")) or v.get("created_by") or "",
                            "share": v.get("share") or _empty_share(),
                            "level": lvl, "devices": counts.get(r["id"], 0)})
            return {"vaults": sorted(out, key=lambda x: x["name"].lower())}

        if method == "POST" and len(parts) == 1:
            name = _s(payload.get("name"), 120)
            if not name:
                return 400, {"error": "nom requis"}
            u = ctx.user or {}
            vid = ctx.store.create(name, {
                "desc": _s(payload.get("desc"), 500), "owner_id": u.get("id"),
                "created_by": u.get("username") or "", "created_at": _now(),
                "share": _clean_share(payload.get("share")),
            }, scope=SCOPE_VAULT)
            ctx.audit("vault_create", f"coffre « {name} »")
            return {"id": vid}

        if len(parts) == 2 and method in ("PUT", "DELETE"):
            got, err = _vault_for(ctx, parts[1], need="admin")
            if err:
                return err
            row, _lvl = got
            if method == "DELETE":
                used = [d for d in _rows(ctx, SCOPE_DEVICE)
                        if d["value"].get("vault_id") == row["id"]]
                if used:
                    # Refus délibéré : supprimer un coffre plein détruirait des secrets
                    # sans que personne n'ait vu ce qu'il contenait.
                    return 409, {"error": f"coffre non vide ({len(used)} équipement(s)) — "
                                          "videz-le ou déplacez son contenu d'abord"}
                ctx.store.delete(row["id"])
                ctx.audit("vault_delete", f"coffre « {row['name']} »")
                return {"ok": True}
            v = dict(row["value"])
            name = row["name"]
            if payload.get("name") is not None:
                name = _s(payload.get("name"), 120) or name
            if payload.get("desc") is not None:
                v["desc"] = _s(payload.get("desc"), 500)
            if payload.get("share") is not None:
                v["share"] = _clean_share(payload.get("share"))
                ctx.audit("vault_share", f"coffre « {name} » : "
                                         + json.dumps(v["share"], ensure_ascii=False))
            ctx.store.update(row["id"], name=name, value=v)
            return {"ok": True}

    # ── Équipements ──
    if head == "devices":
        if method == "GET" and len(parts) == 1:
            allowed = {r["id"]: lvl for r, lvl in _visible_vaults(ctx)}
            want = payload.get("vault")
            if want not in (None, "", "all"):
                try:
                    allowed = {int(want): allowed[int(want)]}
                except (KeyError, TypeError, ValueError):
                    return {"devices": []}
            q = _s(payload.get("q"), 200)
            out = []
            for r in _rows(ctx, SCOPE_DEVICE):
                if r["value"].get("vault_id") not in allowed:
                    continue
                d = _device_public(r, rotate_days)
                d["level"] = allowed[r["value"].get("vault_id")]
                if _device_matches(d, q):
                    out.append(d)
            return {"devices": sorted(out, key=lambda x: x["name"].lower())}

        if method == "POST" and len(parts) == 1:
            got, err = _vault_for(ctx, payload.get("vault_id"), need="write")
            if err:
                return err
            vault, _lvl = got
            name = _s(payload.get("name"), 160)
            if not name:
                return 400, {"error": "nom de l'équipement requis"}
            value = _device_fields(payload, {})
            value["vault_id"] = vault["id"]
            value["accounts"] = _merge_accounts([], payload.get("accounts"), ctx, history_len)
            did = ctx.store.create(name, value, scope=SCOPE_DEVICE)
            ctx.audit("device_create", f"{name} → coffre « {vault['name']} »")
            return {"id": did}

        if len(parts) == 2 and method in ("PUT", "DELETE"):
            row = _row(ctx, SCOPE_DEVICE, parts[1])
            if not row:
                return 404, {"error": "équipement introuvable"}
            got, err = _vault_for(ctx, row["value"].get("vault_id"), need="write")
            if err:
                return err
            vault, _lvl = got
            if method == "DELETE":
                ctx.store.delete(row["id"])
                ctx.audit("device_delete", f"{row['name']} (coffre « {vault['name']} »)")
                return {"ok": True}
            v = dict(row["value"])
            name = row["name"]
            if payload.get("name") is not None:
                name = _s(payload.get("name"), 160) or name
            v.update(_device_fields(payload, v))
            # Déplacement vers un autre coffre : exige aussi l'écriture sur la cible.
            if payload.get("vault_id") is not None and int(payload["vault_id"]) != v.get("vault_id"):
                dest, err = _vault_for(ctx, payload.get("vault_id"), need="write")
                if err:
                    return err
                v["vault_id"] = dest[0]["id"]
                ctx.audit("device_move", f"{name} → coffre « {dest[0]['name']} »")
            if payload.get("accounts") is not None:
                v["accounts"] = _merge_accounts(v.get("accounts"), payload.get("accounts"),
                                                ctx, history_len)
            ctx.store.update(row["id"], name=name, value=v)
            return {"ok": True}

    # ── Révélation d'un secret (le seul chemin qui rend un mot de passe) ──
    if head == "reveal" and method == "GET":
        row = _row(ctx, SCOPE_DEVICE, payload.get("device_id"))
        if not row:
            return 404, {"error": "équipement introuvable"}
        got, err = _vault_for(ctx, row["value"].get("vault_id"), need="read")
        if err:
            return err
        vault, _lvl = got
        acc = next((a for a in (row["value"].get("accounts") or [])
                    if a.get("id") == _s(payload.get("account_id"), 40)), None)
        if not acc:
            return 404, {"error": "accès introuvable"}
        idx = payload.get("index")
        if idx not in (None, "", "current"):
            try:
                hist = (acc.get("history") or [])[int(idx)]
            except (IndexError, TypeError, ValueError):
                return 404, {"error": "entrée d'historique introuvable"}
            blob, what = hist.get("secret"), f"ancien #{idx}"
        else:
            blob, what = acc.get("secret"), "courant"
        if not blob:
            return 404, {"error": "aucun mot de passe enregistré"}
        plain = decrypt(blob)
        if plain is None:
            return 500, {"error": "secret illisible avec la clé courante — la base a-t-elle "
                                  "été restaurée sans son fichier coffre.key ?"}
        # Le geste est nominatif et daté : c'est la contrepartie d'un coffre partagé.
        ctx.audit("reveal", f"{row['name']} / {acc.get('kind')} « {acc.get('login') or '—'} » "
                            f"({what}) — coffre « {vault['name']} »")
        return {"secret": plain}

    if head == "history" and method == "GET":
        row = _row(ctx, SCOPE_DEVICE, payload.get("device_id"))
        if not row:
            return 404, {"error": "équipement introuvable"}
        got, err = _vault_for(ctx, row["value"].get("vault_id"), need="read")
        if err:
            return err
        acc = next((a for a in (row["value"].get("accounts") or [])
                    if a.get("id") == _s(payload.get("account_id"), 40)), None)
        if not acc:
            return 404, {"error": "accès introuvable"}
        return {"history": [{"index": i, "replaced_at": h.get("replaced_at"),
                             "by": h.get("by") or ""}
                            for i, h in enumerate(acc.get("history") or [])]}

    # ── Générateur ──
    if head == "generate" and method == "GET":
        try:
            length = max(8, min(128, int(payload.get("length") or 20)))
        except (TypeError, ValueError):
            length = 20
        return {"password": generate_password(length,
                                              str(payload.get("symbols", "1")) not in ("0", "false"))}

    # ── Export / import ──
    if head == "export" and method == "GET":
        got, err = _vault_for(ctx, payload.get("vault"), need="admin")
        if err:
            return err
        vault, _lvl = got
        return _export_csv(ctx, vault)

    if head == "import" and method == "POST":
        got, err = _vault_for(ctx, payload.get("vault_id"), need="write")
        if err:
            return err
        return _import_csv(ctx, got[0], payload.get("csv") or "", history_len)

    return 404, {"error": f"chemin inconnu : {path}"}


def _device_fields(payload, current):
    """Champs d'identité d'un équipement (hors accès), normalisés."""
    out = dict(current)
    if payload.get("address") is not None:
        out["address"] = _s(payload.get("address"), 200)
    if payload.get("category") is not None:
        cat = _s(payload.get("category"), 40)
        out["category"] = cat if cat in CATEGORY_IDS else "autre"
    for f, ln in (("vendor", 120), ("model", 120), ("site", 120)):
        if payload.get(f) is not None:
            out[f] = _s(payload.get(f), ln)
    if payload.get("notes") is not None:
        out["notes"] = _s(payload.get("notes"), 4000)
    if payload.get("tags") is not None:
        tags = payload.get("tags")
        if isinstance(tags, str):
            tags = re.split(r"[,;]", tags)
        out["tags"] = [t for t in (_s(x, 40) for x in (tags or [])) if t][:20]
    out.setdefault("address", "")
    out.setdefault("category", "autre")
    return out


def generate_password(length=20, symbols=True):
    """Mot de passe aléatoire. Les symboles retenus excluent guillemets, apostrophes,
    barres obliques et espaces : ces caractères se font manger par les shells, les
    fichiers de configuration et les consoles série des équipements broadcast."""
    alphabet = string.ascii_letters + string.digits
    if symbols:
        alphabet += "!#%*+-=?@_~"
    while True:
        pw = "".join(secrets.choice(alphabet) for _ in range(length))
        # Au moins une minuscule, une majuscule et un chiffre : beaucoup d'équipements
        # refusent un mot de passe qui n'a pas les trois.
        if (any(c.islower() for c in pw) and any(c.isupper() for c in pw)
                and any(c.isdigit() for c in pw)):
            return pw


# ─── CSV ────────────────────────────────────────────────────

CSV_FIELDS = ["equipement", "adresse", "categorie", "marque", "modele", "site", "tags",
              "notes", "acces", "libelle", "login", "mot_de_passe", "port", "url",
              "notes_acces"]


def _export_csv(ctx, vault):
    """Export EN CLAIR d'un coffre. Réservé au propriétaire (ou à un admin), journalisé :
    c'est la seule sortie du coffre qui n'est plus protégée par quoi que ce soit."""
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";")
    w.writerow(CSV_FIELDS)
    n_dev = n_acc = 0
    for r in _rows(ctx, SCOPE_DEVICE):
        v = r["value"]
        if v.get("vault_id") != vault["id"]:
            continue
        n_dev += 1
        base = [r["name"], v.get("address") or "", v.get("category") or "",
                v.get("vendor") or "", v.get("model") or "", v.get("site") or "",
                ",".join(v.get("tags") or []), v.get("notes") or ""]
        accounts = v.get("accounts") or []
        if not accounts:
            w.writerow(base + ["", "", "", "", "", "", ""])
            continue
        for a in accounts:
            n_acc += 1
            plain = decrypt(a.get("secret") or "")
            w.writerow(base + [a.get("kind") or "", a.get("label") or "",
                               a.get("login") or "",
                               "" if plain is None else plain,
                               a.get("port") or "", a.get("url") or "",
                               a.get("notes") or ""])
    ctx.audit("export", f"coffre « {vault['name']} » : {n_dev} équipement(s), "
                        f"{n_acc} accès EN CLAIR")
    fname = re.sub(r"[^A-Za-z0-9_.-]+", "_", vault["name"]) or "coffre"
    # utf-8-sig : sans BOM, Excel ouvre les accents en mojibake.
    return Response(buf.getvalue().encode("utf-8-sig"), mimetype="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{fname}.csv"'})


def _import_csv(ctx, vault, text, history_len):
    """Import CSV (mêmes colonnes que l'export). Les lignes partageant un nom
    d'équipement sont regroupées : un équipement, plusieurs accès."""
    if not text.strip():
        return 400, {"error": "fichier vide"}
    try:
        sample = text[:2000]
        dialect = csv.Sniffer().sniff(sample, delimiters=";,\t")
    except csv.Error:
        dialect = csv.excel
        dialect.delimiter = ";"
    rows = list(csv.DictReader(io.StringIO(text), dialect=dialect))
    if not rows:
        return 400, {"error": "aucune ligne exploitable"}
    missing = [c for c in ("equipement",) if c not in (rows[0].keys() or [])]
    if missing:
        return 400, {"error": "colonne « equipement » absente — attendu : "
                              + ", ".join(CSV_FIELDS)}
    existing = {r["name"].lower(): r for r in _rows(ctx, SCOPE_DEVICE)
                if r["value"].get("vault_id") == vault["id"]}
    grouped, errors = {}, []
    for i, row in enumerate(rows, start=2):
        name = _s(row.get("equipement"), 160)
        if not name:
            errors.append(f"ligne {i} : nom d'équipement vide")
            continue
        g = grouped.setdefault(name, {"fields": None, "accounts": []})
        if g["fields"] is None:
            g["fields"] = {
                "address": row.get("adresse"), "category": row.get("categorie"),
                "vendor": row.get("marque"), "model": row.get("modele"),
                "site": row.get("site"), "tags": row.get("tags"), "notes": row.get("notes"),
            }
        kind = _s(row.get("acces"), 40).lower()
        login, pw = _s(row.get("login"), 200), row.get("mot_de_passe")
        if not (kind or login or pw):
            continue
        if kind and kind not in KIND_IDS:
            errors.append(f"ligne {i} : type d'accès « {kind} » inconnu → « other »")
            kind = "other"
        g["accounts"].append({"kind": kind or "other", "label": _s(row.get("libelle"), 120),
                              "login": login, "secret": pw if pw is not None else "",
                              "port": _s(row.get("port"), 20), "url": _s(row.get("url"), 400),
                              "notes": _s(row.get("notes_acces"), 2000)})
    created = updated = 0
    for name, g in grouped.items():
        fields = _device_fields({k: v for k, v in (g["fields"] or {}).items() if v is not None}, {})
        prev = existing.get(name.lower())
        if prev:
            v = dict(prev["value"])
            v.update(fields)
            # Les accès importés s'AJOUTENT à la suite des existants : un import ne doit
            # pas effacer en silence des mots de passe déjà saisis à la main. Le ménage
            # (doublons) reste un geste volontaire, dans l'écran d'édition.
            v["accounts"] = (v.get("accounts") or []) + \
                _merge_accounts([], g["accounts"], ctx, history_len)
            ctx.store.update(prev["id"], value=v)
            updated += 1
        else:
            v = dict(fields)
            v["vault_id"] = vault["id"]
            v["accounts"] = _merge_accounts([], g["accounts"], ctx, history_len)
            ctx.store.create(name, v, scope=SCOPE_DEVICE)
            created += 1
    ctx.audit("import", f"coffre « {vault['name']} » : {created} créé(s), {updated} mis à jour")
    return {"created": created, "updated": updated, "errors": errors[:50]}
