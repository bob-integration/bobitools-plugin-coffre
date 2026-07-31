// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 BOBI SAS, France
// Auteur : Cyril Mazouer, pour le compte de BOBI SAS
// Distribué sous licence GNU GPL v3 (ou ultérieure) ; voir le fichier LICENSE.
//
// Coffre à identifiants — UI. Aucun secret n'est gardé côté client : la liste des accès
// arrive sans mot de passe, et « révéler » / « copier » va chaque fois le chercher au
// backend (qui journalise le geste). Un secret affiché se remasque tout seul.
window.BTTools = window.BTTools || {};
window.BTTools.coffre = (function () {
    let EL = null, CTX = null;
    let META = null, DIR = { users: [], groups: [], roles: [] };
    let vaults = [], devices = [], selected = null, query = "";
    let shareEditing = null, histCtx = null;
    const timers = [];                       // remasquages en attente (purgés au démontage)

    const esc = (window.BT && BT.esc) || ((s) => String(s == null ? "" : s)
        .replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
    const $ = (sel) => EL.querySelector(sel);
    const $$ = (sel) => Array.from(EL.querySelectorAll(sel));
    const tr = (key, fb) => { const v = CTX && CTX.t ? CTX.t(key) : null; return (v && v !== key) ? v : fb; };
    const REVEAL_MS = 30000;                 // durée d'affichage d'un mot de passe révélé

    const kindLabel = (id) => (META.kinds.find((k) => k.id === id) || {}).label || id;
    const catLabel = (id) => (META.categories.find((c) => c.id === id) || {}).label || id;
    const vaultById = (id) => vaults.find((v) => v.id === id);
    const canWrite = (v) => v && (v.level === "write" || v.level === "admin");
    const isOwner = (v) => v && v.level === "admin";

    // ── Presse-papier ────────────────────────────────────────
    // navigator.clipboard n'existe qu'en contexte sécurisé : sur une instance servie en
    // HTTP sur le réseau local (le cas courant ici), il faut le repli par textarea.
    async function copyText(text) {
        try {
            if (navigator.clipboard && window.isSecureContext) {
                await navigator.clipboard.writeText(text); return true;
            }
        } catch (e) { /* on tente le repli */ }
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.setAttribute("readonly", "");
        ta.style.cssText = "position:fixed;top:-1000px;opacity:0";
        document.body.appendChild(ta);
        ta.select();
        let ok = false;
        try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
        document.body.removeChild(ta);
        return ok;
    }

    // ── Chargement ───────────────────────────────────────────
    async function loadAll() {
        META = await CTX.api("meta");
        renderKeyState();
        try { DIR = await CTX.api("directory"); } catch (e) { /* partage indisponible */ }
        await loadVaults();
    }
    async function loadVaults() {
        vaults = (await CTX.api("vaults")).vaults || [];
        if (selected != null && !vaultById(selected)) selected = null;
        if (selected == null && vaults.length) selected = vaults[0].id;
        renderVaults();
        await loadDevices();
    }
    async function loadDevices() {
        if (selected == null) { devices = []; renderDevices(); return; }
        const qs = "?vault=" + encodeURIComponent(selected) + "&q=" + encodeURIComponent(query);
        devices = (await CTX.api("devices" + qs)).devices || [];
        renderDevices();
    }

    // ── Volet des coffres ────────────────────────────────────
    function renderKeyState() {
        const el = $("#cf-key");
        const k = META.key || {};
        if (!k.ok) {
            el.innerHTML = '<div class="cf-key-bad">⚠ Chiffrement indisponible' +
                (k.reason ? ' — ' + esc(k.reason) : '') + '</div>';
            return;
        }
        // L'empreinte permet de vérifier d'un coup d'œil que deux instances (ou une
        // restauration) portent bien la même clé.
        el.innerHTML = '<details><summary title="Clé de chiffrement">🔑 clé ' +
            esc(k.fingerprint) + '</summary><div class="cf-key-info">' +
            'Les mots de passe sont chiffrés avec une clé qui ne se trouve <strong>pas</strong> ' +
            'dans la base. Sauvegardez-la à part : sans elle, une restauration de la base ' +
            'ne rend aucun mot de passe.' +
            (k.source === "file" ? '<div class="mono cf-key-path">' + esc(k.path) + '</div>'
                : '<div class="meta">définie dans config_local.py</div>') +
            '</div></details>';
    }

    function renderVaults() {
        $("#cf-count").textContent = vaults.length ? "(" + vaults.length + ")" : "";
        const ul = $("#cf-vaults");
        if (!vaults.length) {
            ul.innerHTML = '<li class="meta">Aucun coffre. Créez-en un pour ranger vos accès.</li>';
            return;
        }
        ul.innerHTML = vaults.map((v) => {
            const lvl = v.level === "admin" ? "propriétaire" : v.level === "write" ? "écriture" : "lecture";
            return '<li class="cf-vault' + (v.id === selected ? " sel" : "") + '" data-id="' + v.id + '">' +
                '<div class="cf-vault-top"><span class="cf-vault-name">' + esc(v.name) + '</span>' +
                '<span class="cf-chip l-' + esc(v.level) + '">' + lvl + '</span></div>' +
                '<div class="cf-vault-sub">' + v.devices + ' équipement' + (v.devices > 1 ? 's' : '') +
                (v.owner ? ' · ' + esc(v.owner) : '') + '</div>' +
                (v.desc ? '<div class="cf-vault-desc">' + esc(v.desc) + '</div>' : '') + '</li>';
        }).join("");
        ul.querySelectorAll(".cf-vault").forEach((li) => li.onclick = () => {
            selected = +li.dataset.id; renderVaults(); loadDevices();
        });
    }

    // ── Équipements et accès ─────────────────────────────────
    function accountRow(dev, a) {
        const flags = [];
        if (a.stale) flags.push('<span class="cf-flag warn" title="Mot de passe inchangé depuis longtemps">à renouveler</span>');
        if (a.unreadable) flags.push('<span class="cf-flag bad" title="Chiffré avec une autre clé que la clé courante">illisible</span>');
        const target = a.url || linkFor(dev, a);
        const open = target ? '<a class="cf-ico" href="' + esc(target) + '" target="_blank" rel="noopener" title="Ouvrir">↗</a>' : '';
        const acts = a.has_secret
            ? '<button class="cf-ico cf-copy" title="Copier le mot de passe">⧉</button>' +
              '<button class="cf-ico cf-reveal" title="Afficher le mot de passe">👁</button>'
            : '<span class="meta">pas de mot de passe</span>';
        const hist = a.history_count
            ? '<button class="cf-ico cf-hist" title="' + a.history_count + ' ancien(s) mot(s) de passe">🕘</button>' : '';
        return '<div class="cf-acc" data-dev="' + dev.id + '" data-acc="' + esc(a.id) + '">' +
            '<span class="cf-kind k-' + esc(a.kind) + '">' + esc(kindLabel(a.kind)) + '</span>' +
            (a.label ? '<span class="cf-acc-label">' + esc(a.label) + '</span>' : '') +
            '<span class="cf-login mono">' + (a.login ? esc(a.login) : '<span class="meta">sans login</span>') + '</span>' +
            '<span class="cf-secret mono" data-state="hidden">' + (a.has_secret ? '••••••••' : '—') + '</span>' +
            flags.join("") +
            '<span class="cf-acc-actions">' + acts + hist + open + '</span></div>';
    }

    // Lien direct vers l'équipement quand c'est un accès web : évite de retaper l'adresse.
    function linkFor(dev, a) {
        if (!dev.address || a.kind !== "web") return "";
        const port = a.port && a.port !== "443" && a.port !== "80" ? ":" + a.port : "";
        return (a.port === "80" ? "http://" : "https://") + dev.address + port;
    }

    function renderDevices() {
        const box = $("#cf-list");
        const v = vaultById(selected);
        $("#cf-dev-new").disabled = !canWrite(v);
        if (!v) {
            box.innerHTML = '<div class="meta">Sélectionnez un coffre à gauche, ou créez-en un.</div>';
            return;
        }
        if (!devices.length) {
            box.innerHTML = '<div class="meta">' + (query
                ? 'Aucun équipement ne correspond à « ' + esc(query) + ' ».'
                : 'Ce coffre est vide. Ajoutez un équipement pour y ranger ses accès.') + '</div>';
            return;
        }
        box.innerHTML = devices.map((d) => {
            const meta = [d.address ? '<span class="mono">' + esc(d.address) + '</span>' : '',
                          d.site ? esc(d.site) : '',
                          [d.vendor, d.model].filter(Boolean).map(esc).join(" ")]
                .filter(Boolean).join(" · ");
            const tags = (d.tags || []).map((t) => '<span class="cf-tag">' + esc(t) + '</span>').join("");
            const accs = (d.accounts || []).length
                ? d.accounts.map((a) => accountRow(d, a)).join("")
                : '<div class="meta cf-noacc">Aucun accès enregistré.</div>';
            return '<article class="cf-dev" data-id="' + d.id + '">' +
                '<header class="cf-dev-head">' +
                '<span class="cf-cat c-' + esc(d.category) + '">' + esc(catLabel(d.category)) + '</span>' +
                '<h4>' + esc(d.name) + '</h4>' +
                '<span class="cf-dev-meta">' + meta + '</span>' + tags +
                (canWrite(v) ? '<span class="cf-dev-actions">' +
                    '<button class="btn btn-sm cf-edit">Modifier</button>' +
                    '<button class="btn btn-sm btn-red cf-del">Supprimer</button></span>' : '') +
                '</header>' +
                (d.notes ? '<div class="cf-dev-notes">' + esc(d.notes) + '</div>' : '') +
                '<div class="cf-accs">' + accs + '</div></article>';
        }).join("");
        bindDeviceActions();
    }

    function bindDeviceActions() {
        $$(".cf-edit").forEach((b) => b.onclick = () => openDevice(+b.closest(".cf-dev").dataset.id));
        $$(".cf-del").forEach((b) => b.onclick = async () => {
            const d = devices.find((x) => x.id === +b.closest(".cf-dev").dataset.id);
            if (!confirm("Supprimer « " + d.name + " » et tous ses accès ? Les mots de passe seront perdus.")) return;
            try { await CTX.api("devices/" + d.id, { method: "DELETE" }); CTX.toast("Équipement supprimé"); loadVaults(); }
            catch (e) { CTX.toast(e.message, "error"); }
        });
        $$(".cf-reveal").forEach((b) => b.onclick = () => revealInto(b.closest(".cf-acc")));
        $$(".cf-copy").forEach((b) => b.onclick = async () => {
            const row = b.closest(".cf-acc");
            try {
                const r = await CTX.api("reveal?device_id=" + row.dataset.dev + "&account_id=" + encodeURIComponent(row.dataset.acc));
                const done = await copyText(r.secret);
                CTX.toast(done ? "Mot de passe copié" : "Copie refusée par le navigateur — utilisez « afficher »",
                          done ? "info" : "warning");
            } catch (e) { CTX.toast(e.message, "error"); }
        });
        $$(".cf-hist").forEach((b) => b.onclick = () => openHistory(b.closest(".cf-acc")));
    }

    async function revealInto(row) {
        const cell = row.querySelector(".cf-secret");
        if (cell.dataset.state === "shown") { hideSecret(cell); return; }
        try {
            const r = await CTX.api("reveal?device_id=" + row.dataset.dev + "&account_id=" + encodeURIComponent(row.dataset.acc));
            cell.textContent = r.secret;
            cell.dataset.state = "shown";
            cell.classList.add("shown");
            // Remasquage automatique : un écran de régie reste rarement seul.
            timers.push(setTimeout(() => hideSecret(cell), REVEAL_MS));
        } catch (e) { CTX.toast(e.message, "error"); }
    }
    function hideSecret(cell) {
        if (!cell || !cell.isConnected) return;
        cell.textContent = "••••••••"; cell.dataset.state = "hidden"; cell.classList.remove("shown");
    }

    // ── Modale équipement ────────────────────────────────────
    function accountFields(a) {
        a = a || { id: "", kind: "web", label: "", login: "", port: "", url: "", notes: "" };
        const opts = META.kinds.map((k) => '<option value="' + k.id + '"' +
            (k.id === a.kind ? " selected" : "") + ">" + esc(k.label) + "</option>").join("");
        return '<div class="cf-acc-edit" data-id="' + esc(a.id || "") + '">' +
            '<select class="a-kind" aria-label="Type d\'accès">' + opts + '</select>' +
            '<input type="text" class="a-label" maxlength="120" placeholder="libellé (facultatif)" value="' + esc(a.label) + '">' +
            '<input type="text" class="a-login mono" maxlength="200" placeholder="login" value="' + esc(a.login) + '" autocomplete="off">' +
            '<input type="password" class="a-secret mono" maxlength="400" autocomplete="new-password" placeholder="' +
                (a.has_secret ? "mot de passe enregistré — laisser vide pour le garder" : "mot de passe") + '">' +
            '<button type="button" class="cf-ico a-eye" title="Afficher la saisie">👁</button>' +
            '<button type="button" class="cf-ico a-gen" title="Générer un mot de passe">⚄</button>' +
            '<input type="text" class="a-port mono" maxlength="20" placeholder="port" value="' + esc(a.port) + '">' +
            '<input type="text" class="a-url mono" maxlength="400" placeholder="URL (si différente de l\'adresse)" value="' + esc(a.url) + '">' +
            '<button type="button" class="cf-ico a-del" title="Retirer cet accès">✕</button></div>';
    }
    function bindAccountFields() {
        $$(".a-del").forEach((b) => b.onclick = () => b.closest(".cf-acc-edit").remove());
        $$(".a-eye").forEach((b) => b.onclick = () => {
            const i = b.closest(".cf-acc-edit").querySelector(".a-secret");
            i.type = i.type === "password" ? "text" : "password";
        });
        $$(".a-gen").forEach((b) => b.onclick = async () => {
            try {
                const r = await CTX.api("generate?length=20");
                const i = b.closest(".cf-acc-edit").querySelector(".a-secret");
                i.value = r.password; i.type = "text";
                CTX.toast("Mot de passe généré — pensez à l'appliquer sur l'équipement");
            } catch (e) { CTX.toast(e.message, "error"); }
        });
    }

    function openDevice(id) {
        const d = id ? devices.find((x) => x.id === id) : null;
        const f = $("#cf-dev-form");
        f.reset();
        $("#cf-dev-title").textContent = d ? "Modifier « " + d.name + " »" : "Nouvel équipement";
        $("#cf-dev-cat").innerHTML = META.categories.map((c) =>
            '<option value="' + c.id + '">' + esc(c.label) + "</option>").join("");
        if (d) {
            ["name", "address", "vendor", "model", "site", "notes"].forEach((k) => f[k].value = d[k] || "");
            f.category.value = d.category || "autre";
            f.tags.value = (d.tags || []).join(", ");
        }
        f.dataset.id = d ? d.id : "";
        $("#cf-acc-list").innerHTML = (d && d.accounts.length ? d.accounts : [null]).map(accountFields).join("");
        bindAccountFields();
        $("#cf-dev-modal").hidden = false;
        f.name.focus();
    }

    function collectAccounts() {
        return $$("#cf-acc-list .cf-acc-edit").map((row) => {
            const val = (cls) => row.querySelector(cls).value.trim();
            const a = { kind: val(".a-kind"), label: val(".a-label"), login: val(".a-login"),
                        port: val(".a-port"), url: val(".a-url") };
            if (row.dataset.id) a.id = row.dataset.id;
            // Champ vide = mot de passe inchangé : l'UI ne connaît pas les secrets et ne
            // doit jamais pouvoir en effacer un par simple ré-enregistrement.
            const s = row.querySelector(".a-secret").value;
            if (s) a.secret = s;
            return a;
        }).filter((a) => a.login || a.secret || a.label || a.url);
    }

    async function saveDevice(ev) {
        ev.preventDefault();
        const f = $("#cf-dev-form");
        const body = { name: f.name.value, address: f.address.value, category: f.category.value,
                       vendor: f.vendor.value, model: f.model.value, site: f.site.value,
                       notes: f.notes.value, tags: f.tags.value, accounts: collectAccounts() };
        try {
            if (f.dataset.id) await CTX.api("devices/" + f.dataset.id, { method: "PUT", body });
            else { body.vault_id = selected; await CTX.api("devices", { body }); }
            $("#cf-dev-modal").hidden = true;
            CTX.toast("Enregistré");
            loadVaults();
        } catch (e) { CTX.toast(e.message, "error"); }
    }

    // ── Partage ──────────────────────────────────────────────
    function shareRows(kind, items, current, labelOf) {
        const cur = {};
        (current[kind] || []).forEach((e) => cur[e.id] = e.level);
        if (!items.length) return '<div class="meta">—</div>';
        return items.map((it) => {
            const lvl = cur[it.id] || "";
            return '<label class="cf-share-row"><input type="checkbox" class="s-on" data-kind="' + kind +
                '" data-id="' + esc(String(it.id)) + '"' + (lvl ? " checked" : "") + '> ' +
                esc(labelOf(it)) + ' <select class="s-lvl"' + (lvl ? "" : " disabled") + '>' +
                '<option value="read"' + (lvl === "read" ? " selected" : "") + '>lecture</option>' +
                '<option value="write"' + (lvl === "write" ? " selected" : "") + '>écriture</option>' +
                '</select></label>';
        }).join("");
    }
    function openShare() {
        const v = vaultById(selected);
        if (!v) return;
        if (!isOwner(v)) { CTX.toast("Seul le propriétaire peut partager ce coffre", "warning"); return; }
        shareEditing = v;
        $("#cf-share-name").textContent = "« " + v.name + " »";
        const me = (META.me || {}).id;
        const cur = v.share || { users: [], groups: [], roles: [] };
        $("#cf-share-users").innerHTML = shareRows("users", DIR.users.filter((u) => u.id !== me), cur,
            (u) => u.username + (u.prenom || u.nom ? " (" + [u.prenom, u.nom].filter(Boolean).join(" ") + ")" : ""));
        $("#cf-share-groups").innerHTML = shareRows("groups", DIR.groups, cur,
            (g) => g.name + " (" + (g.members || []).length + ")");
        $("#cf-share-roles").innerHTML = shareRows("roles", DIR.roles, cur, (r) => r.label);
        $$("#cf-share-modal .s-on").forEach((c) => c.onchange = () => {
            c.parentElement.querySelector(".s-lvl").disabled = !c.checked;
        });
        $("#cf-share-modal").hidden = false;
    }
    async function saveShare() {
        const share = { users: [], groups: [], roles: [] };
        $$("#cf-share-modal .s-on").forEach((c) => {
            if (!c.checked) return;
            const kind = c.dataset.kind;
            const id = kind === "roles" ? c.dataset.id : +c.dataset.id;
            share[kind].push({ id, level: c.parentElement.querySelector(".s-lvl").value });
        });
        try {
            await CTX.api("vaults/" + shareEditing.id, { method: "PUT", body: { share } });
            $("#cf-share-modal").hidden = true;
            CTX.toast("Partage enregistré");
            loadVaults();
        } catch (e) { CTX.toast(e.message, "error"); }
    }

    // ── Historique ───────────────────────────────────────────
    async function openHistory(row) {
        histCtx = { dev: row.dataset.dev, acc: row.dataset.acc };
        const box = $("#cf-hist-list");
        box.innerHTML = '<div class="meta">Chargement…</div>';
        $("#cf-hist-modal").hidden = false;
        try {
            const r = await CTX.api("history?device_id=" + histCtx.dev + "&account_id=" + encodeURIComponent(histCtx.acc));
            box.innerHTML = (r.history || []).map((h) =>
                '<div class="cf-hist-row"><span>' + esc(h.replaced_at || "") + '</span>' +
                '<span class="meta">remplacé par ' + esc(h.by || "?") + '</span>' +
                '<span class="cf-secret mono" data-state="hidden">••••••••</span>' +
                '<button class="cf-ico h-reveal" data-i="' + h.index + '" title="Afficher">👁</button>' +
                '<button class="cf-ico h-copy" data-i="' + h.index + '" title="Copier">⧉</button></div>').join("")
                || '<div class="meta">Aucune rotation enregistrée.</div>';
            box.querySelectorAll(".h-reveal").forEach((b) => b.onclick = async () => {
                const cell = b.parentElement.querySelector(".cf-secret");
                if (cell.dataset.state === "shown") { hideSecret(cell); return; }
                const r2 = await CTX.api("reveal?device_id=" + histCtx.dev + "&account_id=" +
                    encodeURIComponent(histCtx.acc) + "&index=" + b.dataset.i);
                cell.textContent = r2.secret; cell.dataset.state = "shown"; cell.classList.add("shown");
                timers.push(setTimeout(() => hideSecret(cell), REVEAL_MS));
            });
            box.querySelectorAll(".h-copy").forEach((b) => b.onclick = async () => {
                const r2 = await CTX.api("reveal?device_id=" + histCtx.dev + "&account_id=" +
                    encodeURIComponent(histCtx.acc) + "&index=" + b.dataset.i);
                CTX.toast(await copyText(r2.secret) ? "Copié" : "Copie refusée par le navigateur");
            });
        } catch (e) { box.innerHTML = '<div class="meta">' + esc(e.message) + "</div>"; }
    }

    // ── Import / export ──────────────────────────────────────
    async function runImport() {
        const v = vaultById(selected);
        const text = $("#cf-imp-text").value;
        if (!text.trim()) { CTX.toast("Choisissez un fichier ou collez le contenu", "warning"); return; }
        try {
            const r = await CTX.api("import", { body: { vault_id: v.id, csv: text } });
            const res = $("#cf-imp-res");
            res.hidden = false;
            res.innerHTML = '<strong>' + r.created + ' créé(s), ' + r.updated + ' mis à jour.</strong>' +
                ((r.errors || []).length ? '<ul>' + r.errors.map((x) => '<li>' + esc(x) + '</li>').join("") + '</ul>' : "");
            $("#cf-imp-text").value = "";
            loadVaults();
        } catch (e) { CTX.toast(e.message, "error"); }
    }

    // ── Montage ──────────────────────────────────────────────
    function applyI18n(root) {
        root.querySelectorAll("[data-i18n]").forEach((n) => {
            const v = tr(n.getAttribute("data-i18n"), null);
            if (v) n.textContent = v;
        });
        root.querySelectorAll("[data-i18n-ph]").forEach((n) => {
            const v = tr(n.getAttribute("data-i18n-ph"), null);
            if (v) n.setAttribute("placeholder", v);
        });
    }

    function bindOnce() {
        $("#cf-vault-new").onclick = async () => {
            const name = prompt("Nom du nouveau coffre (ex. « Régie A », « Cars », « Infra réseau ») :");
            if (!name) return;
            try {
                const r = await CTX.api("vaults", { body: { name } });
                selected = r.id; CTX.toast("Coffre créé"); loadVaults();
            } catch (e) { CTX.toast(e.message, "error"); }
        };
        $("#cf-dev-new").onclick = () => openDevice(null);
        $("#cf-dev-cancel").onclick = () => { $("#cf-dev-modal").hidden = true; };
        $("#cf-dev-form").onsubmit = saveDevice;
        $("#cf-acc-add").onclick = () => {
            $("#cf-acc-list").insertAdjacentHTML("beforeend", accountFields(null));
            bindAccountFields();
        };
        let deb = null;
        $("#cf-q").oninput = (e) => {
            query = e.target.value;
            clearTimeout(deb); deb = setTimeout(loadDevices, 200);
        };
        $("#cf-share").onclick = () => { $("#cf-io-menu").open = false; openShare(); };
        $("#cf-share-cancel").onclick = () => { $("#cf-share-modal").hidden = true; };
        $("#cf-share-save").onclick = saveShare;
        $("#cf-hist-close").onclick = () => { $("#cf-hist-modal").hidden = true; };
        $("#cf-import").onclick = () => { $("#cf-io-menu").open = false; $("#cf-imp-res").hidden = true; $("#cf-imp-modal").hidden = false; };
        $("#cf-imp-cancel").onclick = () => { $("#cf-imp-modal").hidden = true; };
        $("#cf-imp-go").onclick = runImport;
        $("#cf-imp-file").onchange = (e) => {
            const f = e.target.files[0];
            if (!f) return;
            const rd = new FileReader();
            rd.onload = () => { $("#cf-imp-text").value = rd.result; };
            rd.readAsText(f, "utf-8");
        };
        $("#cf-export").onclick = () => {
            $("#cf-io-menu").open = false;
            const v = vaultById(selected);
            if (!v) return;
            if (!isOwner(v)) { CTX.toast("Export réservé au propriétaire du coffre", "warning"); return; }
            if (!confirm("L'export contient TOUS les mots de passe de « " + v.name + " » EN CLAIR.\n" +
                         "Le téléchargement est journalisé. Continuer ?")) return;
            window.location = "/api/tools/coffre/export?vault=" + encodeURIComponent(v.id);
        };
        $("#cf-vault-del").onclick = async () => {
            $("#cf-io-menu").open = false;
            const v = vaultById(selected);
            if (!v || !isOwner(v)) { CTX.toast("Seul le propriétaire peut supprimer ce coffre", "warning"); return; }
            if (!confirm("Supprimer le coffre « " + v.name + " » ?")) return;
            try { await CTX.api("vaults/" + v.id, { method: "DELETE" }); selected = null; CTX.toast("Coffre supprimé"); loadVaults(); }
            catch (e) { CTX.toast(e.message, "error"); }
        };
        // Fermeture des modales au clic sur le fond et à Échap.
        $$(".cf-modal").forEach((m) => m.onclick = (e) => { if (e.target === m) m.hidden = true; });
        EL.addEventListener("keydown", (e) => {
            if (e.key === "Escape") $$(".cf-modal").forEach((m) => m.hidden = true);
        });
    }

    return {
        async mount(el, ctx) {
            EL = el; CTX = ctx;
            selected = null; query = ""; devices = []; vaults = [];
            applyI18n(el);
            bindOnce();
            try { await loadAll(); }
            catch (e) {
                $("#cf-list").innerHTML = '<div class="meta">' + esc(e.message) + "</div>";
                CTX.toast(e.message, "error");
            }
        },
        unmount() {
            timers.splice(0).forEach(clearTimeout);
            EL = null; CTX = null;
        },
    };
})();
