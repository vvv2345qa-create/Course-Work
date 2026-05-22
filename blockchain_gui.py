import customtkinter as ctk
import tkinter as tk
import threading, time, hashlib, uuid, random, string
from datetime import datetime
from typing import Optional

from blockchain_core import (
    Blockchain, Block, VendorTransaction, UserTransaction,
    Registry, hash_software, DIFFICULTY
)

# ── Тема ──────────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

C = dict(
    bg="#0b0f1c", panel="#111827", card="#1a2236", border="#1e3a5f",
    accent="#00d4ff", purple="#7c3aed", green="#10b981", red="#ef4444",
    orange="#f59e0b", text="#e2e8f0", muted="#64748b",
    vendor="#3b82f6", user="#8b5cf6", atk="#ef4444",
)
MN  = ("Courier New", 10)
MNS = ("Courier New", 9)
MNB = ("Courier New", 10, "bold")
MNL = ("Courier New", 13, "bold")


def ts(): return datetime.now().strftime("%H:%M:%S")

def dk(h):
    try: r,g,b=int(h[1:3],16),int(h[3:5],16),int(h[5:7],16); return f"#{max(r-28,0):02x}{max(g-28,0):02x}{max(b-28,0):02x}"
    except: return h

def rnd_hash():
    return hashlib.sha256(("EVIL-"+"".join(random.choices(string.ascii_letters,k=24))).encode()).hexdigest()


# ══════════════════════════════════════════════════════════════════════════════
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("⛓  Blockchain Supply-Chain Guard")
        self.geometry("1560x980")
        self.configure(fg_color=C["bg"])
        self.resizable(True, True)

        # ── Данные ────────────────────────────────────────────────────────
        self.registry = Registry()
        self.vchain   = Blockchain("vendor")
        self.uchain   = Blockchain("user")

        # Каталог ПО выпущенного вендором: tx_id → {name, version, hash, vendor, label}
        self.catalog: dict = {}

        # Состояние Vendor pipeline
        self.v_tx    = None; self.v_blk = None; self.v_mined = None

        self.u_tx    = None; self.u_blk = None; self.u_mined = None
        self.u_rejected_reason: str = ""   # причина отклонения

        # Состояние Attacker pipeline
        self.a_tx    = None; self.a_blk = None; self.a_mined = None

        for v in ["VendorCorp", "TrustSoft", "OpenSourceOrg"]:
            self.registry.register_vendor(v)
        for u in ["alice", "bob", "charlie"]:
            self.registry.register_user(u)
        self.registry.register_user("attacker")

        self._build_ui()
        self._log("✅ Система запущена. Блокчейны пусты.", "green")
        self._redraw()

    def _build_ui(self):
        hdr = ctk.CTkFrame(self, fg_color=C["panel"], height=56)
        hdr.pack(fill="x"); hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="⛓  BLOCKCHAIN SUPPLY-CHAIN GUARD",
                     font=("Courier New", 20, "bold"), text_color=C["accent"]).pack(side="left", padx=20)
        ctk.CTkLabel(hdr, text=f"PoW difficulty: {DIFFICULTY} нулей",
                     font=MNS, text_color=C["muted"]).pack(side="right", padx=12)
        self.lbl_st = ctk.CTkLabel(hdr, text="● АКТИВНА", font=MNB, text_color=C["green"])
        self.lbl_st.pack(side="right", padx=20)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=8, pady=6)

        left = ctk.CTkFrame(body, fg_color="transparent", width=400)
        left.pack(side="left", fill="y", padx=(0,6)); left.pack_propagate(False)

        right = ctk.CTkFrame(body, fg_color="transparent")
        right.pack(side="left", fill="both", expand=True)

        self._build_tabs(left)
        self._build_chains(right)

    # ── Вкладки ───────────────────────────────────────────────────────────
    def _build_tabs(self, p):
        self.tabs = ctk.CTkTabview(p, fg_color=C["panel"],
            segmented_button_fg_color=C["card"],
            segmented_button_selected_color=C["accent"],
            segmented_button_selected_hover_color="#00b3d4",
            segmented_button_unselected_color=C["card"],
            segmented_button_unselected_hover_color=C["border"],
            text_color=C["text"], border_color=C["border"], border_width=1)
        self.tabs.pack(fill="both", expand=True)
        self.tabs.add("🏭 Вендор")
        self.tabs.add("👤 Пользователь")
        self.tabs.add("☠️ Злоумышленник")
        self.tabs.add("✅ Валидация")
        self._tab_vendor(self.tabs.tab("🏭 Вендор"))
        self._tab_user(self.tabs.tab("👤 Пользователь"))
        self._tab_attacker(self.tabs.tab("☠️ Злоумышленник"))
        self._tab_validation(self.tabs.tab("✅ Валидация"))


    def _tab_vendor(self, p):
        sf = ctk.CTkScrollableFrame(p, fg_color="transparent"); sf.pack(fill="both", expand=True)

        self._sec(sf, "🏭 ПОСТАВЩИК ВЫПУСКАЕТ ПО")
        ctk.CTkLabel(sf,
            text="Хэш ПО вычисляется автоматически: SHA-256(название::версия).\n"
                 "Поставщик подписывает транзакцию своим приватным ключом.",
            font=MNS, text_color=C["muted"], justify="left").pack(anchor="w", padx=10, pady=(2,8))

        self.v_vendor = self._cmb(sf, "Поставщик:", ["VendorCorp", "TrustSoft", "OpenSourceOrg"])
        self.v_name   = self._ent(sf, "Название ПО:", "OpenSSL")
        self.v_ver    = self._ent(sf, "Версия:", "3.2.1")
        self.v_desc   = self._ent(sf, "Описание:", "Криптографическая библиотека")

        self._sec(sf, "🔑 ХЭШ (вычисляется автоматически)")
        self.v_hash_box = self._txbox(sf, 34, C["accent"])
        self.v_name.bind("<KeyRelease>", lambda e: self._v_update_hash())
        self.v_ver.bind("<KeyRelease>",  lambda e: self._v_update_hash())
        self._v_update_hash()

        self._sec(sf, "⚡ ШАГИ")
        self.btn_v1 = self._btn(sf, "1. Создать транзакцию", C["vendor"], self._v_create_tx)
        self.btn_v2 = self._btn(sf, "2. Создать блок",        C["card"],   self._v_create_blk)
        self.btn_v3 = self._btn(sf, "3. Майнинг (PoW)",       C["purple"], self._v_mine)
        self.btn_v4 = self._btn(sf, "4. Добавить в цепь",     C["green"],  self._v_add)

        self._sec(sf, "📋 ТЕКУЩАЯ ТРАНЗАКЦИЯ")
        self.v_tx_box = self._txbox(sf, 120, C["vendor"])
        self._v_btns()

    # ═══════════════════════════════════════════════════════════════════════
    #  ВКЛАДКА: ПОЛЬЗОВАТЕЛЬ (легитимный)
    # ═══════════════════════════════════════════════════════════════════════
    def _tab_user(self, p):
        sf = ctk.CTkScrollableFrame(p, fg_color="transparent"); sf.pack(fill="both", expand=True)

        self._sec(sf, "👤 ЛЕГИТИМНЫЙ ПОЛЬЗОВАТЕЛЬ")
        ctk.CTkLabel(sf,
            text="Пользователь скачивает ПО из каталога вендора.\n"
                 "Если злоумышленник успел раньше — блок будет отклонён:\n"
                 "«ПО уже зарегистрировано в цепи».",
            font=MNS, text_color=C["muted"], justify="left").pack(anchor="w", padx=10, pady=(2,8))

        self.u_user = self._cmb(sf, "Пользователь:", ["alice", "bob", "charlie"])

        self._sec(sf, "📦 ВЫБОР ПО ИЗ КАТАЛОГА")
        self.u_sw = ctk.CTkComboBox(sf, values=["(сначала вендор должен выпустить ПО)"],
                                     font=MNS, fg_color=C["card"], border_color=C["border"],
                                     button_color=C["border"], dropdown_fg_color=C["panel"],
                                     text_color=C["text"], command=self._u_sw_pick)
        self.u_sw.pack(fill="x", padx=8, pady=4)

        # Показываем легитимный хэш (readonly)
        ctk.CTkLabel(sf, text="Легитимный хэш от вендора:", font=MNS, text_color=C["muted"]).pack(anchor="w", padx=10, pady=(6,0))
        self.u_legit_var = tk.StringVar(value="—")
        ctk.CTkEntry(sf, textvariable=self.u_legit_var, font=MNS,
                     fg_color=C["bg"], border_color=C["border"],
                     text_color=C["green"], state="disabled").pack(fill="x", padx=8, pady=2)

        self.u_url = self._ent(sf, "URL загрузки:", "https://repo.vendor.io/package.tar.gz")

        self._sec(sf, "⚡ ШАГИ")
        self.btn_u1 = self._btn(sf, "1. Создать транзакцию", C["user"],   self._u_create_tx)
        self.btn_u2 = self._btn(sf, "2. Создать блок",        C["card"],   self._u_create_blk)
        self.btn_u3 = self._btn(sf, "3. Майнинг (PoW)",       C["purple"], self._u_mine)
        self.btn_u4 = self._btn(sf, "4. Добавить в цепь",     C["green"],  self._u_add)

        self._sec(sf, "📋 ТЕКУЩАЯ ТРАНЗАКЦИЯ")
        self.u_tx_box = self._txbox(sf, 100, C["user"])

        # Поле статуса / отклонения
        self.u_status_lbl = ctk.CTkLabel(sf, text="", font=("Courier New", 10, "bold"),
                                          text_color=C["orange"], wraplength=360, justify="left")
        self.u_status_lbl.pack(anchor="w", padx=10, pady=4)
        self._u_btns()

    # ═══════════════════════════════════════════════════════════════════════
    #  ВКЛАДКА: ЗЛОУМЫШЛЕННИК
    # ═══════════════════════════════════════════════════════════════════════
    def _tab_attacker(self, p):
        sf = ctk.CTkScrollableFrame(p, fg_color="transparent"); sf.pack(fill="both", expand=True)

        self._sec(sf, "☠️ ЗЛОУМЫШЛЕННИК")
        ctk.CTkLabel(sf,
            text="Злоумышленник создаёт транзакцию на то же ПО,\n"
                 "но подменяет downloaded_hash (вредоносный файл).\n"
                 "Имея >51% мощности — майнит блок БЫСТРЕЕ легитимного\n"
                 "и добавляет его в цепь первым.\n"
                 "После этого блок легитимного пользователя отклоняется.",
            font=MNS, text_color=C["orange"], justify="left").pack(anchor="w", padx=10, pady=(2,10))

        self._sec(sf, "🎯 ЦЕЛЕВОЕ ПО")
        self.a_sw = ctk.CTkComboBox(sf, values=["(сначала вендор должен выпустить ПО)"],
                                     font=MNS, fg_color=C["card"], border_color=C["red"],
                                     button_color=C["red"], dropdown_fg_color=C["panel"],
                                     text_color=C["text"], command=self._a_sw_pick)
        self.a_sw.pack(fill="x", padx=8, pady=4)

        self._sec(sf, "👤 ЦЕЛЕВОЙ ПОЛЬЗОВАТЕЛЬ")
        self.a_target_user = self._cmb(sf, "Выбрать жертву (UID):", ["alice", "bob", "charlie"])

        ctk.CTkLabel(sf, text="Легитимный хэш (для сравнения):", font=MNS, text_color=C["muted"]).pack(anchor="w", padx=10, pady=(4,0))
        self.a_legit_var = tk.StringVar(value="—")
        ctk.CTkEntry(sf, textvariable=self.a_legit_var, font=MNS,
                     fg_color=C["bg"], border_color=C["border"],
                     text_color=C["green"], state="disabled").pack(fill="x", padx=8, pady=2)

        # Поддельный хэш
        ctk.CTkLabel(sf, text="Поддельный хэш (подменяется злоумышленником):", font=MNS, text_color=C["muted"]).pack(anchor="w", padx=10, pady=(6,0))
        hf = ctk.CTkFrame(sf, fg_color="transparent")
        hf.pack(fill="x", padx=8, pady=2)
        self.a_fake_var = tk.StringVar(value=rnd_hash())
        ctk.CTkEntry(hf, textvariable=self.a_fake_var, font=MNS,
                     fg_color=C["card"], border_color=C["red"],
                     text_color=C["atk"]).pack(side="left", fill="x", expand=True)
        ctk.CTkButton(hf, text="⟳", width=32, fg_color=C["red"], hover_color=dk(C["red"]),
                      command=lambda: self.a_fake_var.set(rnd_hash())).pack(side="right", padx=4)

        ctk.CTkLabel(sf, text="⚡ Злоумышленник стартует с nonce=50000 (имитация >51% мощности)",
                     font=("Courier New", 8), text_color=C["muted"]).pack(anchor="w", padx=10)

        self._sec(sf, "⚡ ШАГИ")
        self.btn_a1 = self._btn(sf, "1. Создать транзакцию (с поддельным хэшем)", C["atk"], self._a_create_tx)
        self.btn_a2 = self._btn(sf, "2. Создать блок",                             C["card"], self._a_create_blk)
        self.btn_a3 = self._btn(sf, "3. Майнинг (БЫСТРЫЙ — >51% мощности)",       C["red"],  self._a_mine)
        self.btn_a4 = self._btn(sf, "4. Добавить в цепь ПЕРВЫМ",                  C["orange"],self._a_add)

        self._sec(sf, "📋 ПОДДЕЛЬНАЯ ТРАНЗАКЦИЯ")
        self.a_tx_box = self._txbox(sf, 100, C["atk"])
        self._a_btns()

    # ═══════════════════════════════════════════════════════════════════════
    #  ВКЛАДКА: ВАЛИДАЦИЯ
    # ═══════════════════════════════════════════════════════════════════════
    def _tab_validation(self, p):
        sf = ctk.CTkScrollableFrame(p, fg_color="transparent"); sf.pack(fill="both", expand=True)

        self._sec(sf, "🔍 ПРОВЕРКА СТРУКТУРЫ")
        self._btn(sf, "Структура Vendor-цепи", C["vendor"], lambda: self._val_struct("vendor"))
        self._btn(sf, "Структура User-цепи",   C["user"],   lambda: self._val_struct("user"))

        self._sec(sf, "🔐 СВЕРКА ХЭШЕЙ (vendor ↔ user)")
        ctk.CTkLabel(sf,
            text="Сравнивает downloaded_hash из user-транзакции\n"
                 "с эталонным software_hash из vendor-транзакции.\n"
                 "Несовпадение = в цепи зафиксирована SSC-атака.",
            font=MNS, text_color=C["muted"], justify="left").pack(anchor="w", padx=10, pady=4)
        self._btn(sf, "🔎 Сверить хэши ПО", C["green"], self._val_hashes)

        self._sec(sf, "📊 РЕЗУЛЬТАТ")
        self.val_box = self._txbox(sf, 380, C["text"])

    # ══════════════════════════════════════════════════════════════════════
    #  Правая панель: цепи + лог
    # ══════════════════════════════════════════════════════════════════════
    def _build_chains(self, p):
        chains = ctk.CTkFrame(p, fg_color="transparent")
        chains.pack(fill="both", expand=True)

        # Vendor chain
        vf = ctk.CTkFrame(chains, fg_color=C["panel"], border_color=C["vendor"], border_width=1, corner_radius=8)
        vf.pack(side="left", fill="both", expand=True, padx=(0,4))
        ctk.CTkLabel(vf, text="🏭  VENDOR BLOCKCHAIN", font=MNL, text_color=C["vendor"]).pack(pady=(8,2))
        self.vsf = ctk.CTkScrollableFrame(vf, fg_color="transparent", scrollbar_button_color=C["vendor"])
        self.vsf.pack(fill="both", expand=True, padx=6, pady=6)

        # User chain
        uf = ctk.CTkFrame(chains, fg_color=C["panel"], border_color=C["user"], border_width=1, corner_radius=8)
        uf.pack(side="left", fill="both", expand=True, padx=(4,0))
        ctk.CTkLabel(uf, text="👤  USER BLOCKCHAIN", font=MNL, text_color=C["user"]).pack(pady=(8,2))
        self.usf = ctk.CTkScrollableFrame(uf, fg_color="transparent", scrollbar_button_color=C["user"])
        self.usf.pack(fill="both", expand=True, padx=6, pady=6)

        # Лог
        lf = ctk.CTkFrame(p, fg_color=C["panel"], border_color=C["border"], border_width=1, corner_radius=8)
        lf.pack(fill="x", pady=(6,0))
        lh = ctk.CTkFrame(lf, fg_color="transparent"); lh.pack(fill="x", padx=10, pady=4)
        ctk.CTkLabel(lh, text="📟  СИСТЕМНЫЙ ЛОГ", font=MNB, text_color=C["accent"]).pack(side="left")
        ctk.CTkButton(lh, text="Очистить", width=70, height=24, fg_color=C["card"],
                       text_color=C["muted"], font=MNS, command=self._log_clear).pack(side="right")
        self.log_w = tk.Text(lf, height=9, bg=C["card"], fg=C["text"],
                              font=("Courier New", 9), bd=0, relief="flat")
        self.log_w.pack(fill="x", padx=8, pady=(0,8))
        for t, c in [("green",C["green"]),("red",C["red"]),("orange",C["orange"]),
                     ("accent",C["accent"]),("muted",C["muted"]),
                     ("vendor",C["vendor"]),("user",C["user"]),("atk",C["atk"])]:
            self.log_w.tag_config(t, foreground=c)
        self.log_w.configure(state="disabled")

    # ══════════════════════════════════════════════════════════════════════
    #  ВЕНДОР — логика
    # ══════════════════════════════════════════════════════════════════════
    def _v_update_hash(self):
        n, v = self.v_name.get().strip(), self.v_ver.get().strip()
        h = hash_software(n, v) if (n and v) else "—"
        self.v_hash_box.configure(state="normal"); self.v_hash_box.delete("1.0","end")
        self.v_hash_box.insert("end", h); self.v_hash_box.configure(state="disabled")

    def _v_create_tx(self):
        vid  = self.v_vendor.get()
        keys = self.registry.vendor_keys(vid)
        name = self.v_name.get().strip(); ver = self.v_ver.get().strip()
        if not (name and ver):
            self._log("[VENDOR] Заполните название и версию ПО!", "orange"); return
        tx_id  = "VTX-" + uuid.uuid4().hex[:8].upper()
        sw_hash = hash_software(name, ver)
        tx = VendorTransaction(tx_id=tx_id, vendor_id=vid,
            vendor_public_key=keys["public"], software_name=name,
            version=ver, software_hash=sw_hash,
            description=self.v_desc.get().strip(), release_timestamp=time.time())
        tx.do_sign(keys["private"])
        self.v_tx = tx.to_dict(); self.v_blk = self.v_mined = None
        self.catalog[tx_id] = dict(label=f"{name} v{ver}  [{vid}]",
                                    name=name, version=ver, hash=sw_hash,
                                    vendor=vid, tx_id=tx_id)
        self._refresh_sw_combos()
        self._fill_box(self.v_tx_box, self.v_tx, C["vendor"]); self._v_btns()
        self._log(f"[VENDOR] TX {tx_id}: {name} v{ver} hash={sw_hash[:18]}...", "vendor")

    def _v_create_blk(self):
        if not self.v_tx: self._log("[VENDOR] Нет TX!", "orange"); return
        self.vchain.pending_transactions = [self.v_tx]
        self.v_blk = self.vchain.create_block("Miner-V"); self.v_mined = None
        self._v_btns(); self._log(f"[VENDOR] Блок #{self.v_blk.index} создан", "vendor")

    def _v_mine(self):
        if not self.v_blk: return
        blk = self.v_blk; self._status("⏳ МАЙНИНГ...", C["orange"])
        self._log(f"[VENDOR] Майнинг блока #{blk.index}...", "muted")
        def _r():
            it = blk.mine()
            self.v_mined = blk; self.v_blk = None
            self.after(0, lambda: self._log(f"[VENDOR] ✅ Hash={blk.hash[:18]}... Nonce={blk.nonce} Iter={it}", "green"))
            self.after(0, lambda: self._status("● АКТИВНА", C["green"]))
            self.after(0, self._v_btns)
        threading.Thread(target=_r, daemon=True).start()

    def _v_add(self):
        if not self.v_mined: return
        ok, reason = self.vchain.add_block(self.v_mined)
        if ok:
            self._log(f"[VENDOR] ✅ Блок #{self.v_mined.index} добавлен. Цепь: {len(self.vchain.chain)}", "green")
            self.v_tx = self.v_blk = self.v_mined = None
            self._fill_box(self.v_tx_box, None, C["vendor"]); self._v_btns(); self._redraw()
        else:
            self._log(f"[VENDOR] ❌ Отклонён: {reason}", "red")

    def _v_btns(self):
        self._sbtn(self.btn_v1, True, C["vendor"])
        self._sbtn(self.btn_v2, bool(self.v_tx and not self.v_blk and not self.v_mined), C["card"])
        self._sbtn(self.btn_v3, bool(self.v_blk), C["purple"])
        self._sbtn(self.btn_v4, bool(self.v_mined), C["green"])

    # ══════════════════════════════════════════════════════════════════════
    #  ПОЛЬЗОВАТЕЛЬ (легитимный) — логика
    # ══════════════════════════════════════════════════════════════════════
    def _u_sw_pick(self, label: str):
        entry = self._by_label(label)
        if entry:
            self.u_legit_var.set(entry["hash"])

    def _u_create_tx(self):
        uid   = self.u_user.get()
        keys  = self.registry.user_keys(uid)
        entry = self._by_label(self.u_sw.get())
        if not entry:
            self._log("[USER] Выберите ПО из каталога!", "orange"); return
        pid   = "PID-U-" + uuid.uuid4().hex[:6].upper()
        tx_id = "UTX-"   + uuid.uuid4().hex[:8].upper()
        dh = entry["hash"]
        tx = UserTransaction(tx_id=tx_id, pid=pid, actor="user",
            user_id=uid, user_public_key=keys["public"],
            software_name=entry["name"], version=entry["version"],
            downloaded_hash=dh, vendor_tx_id=entry["tx_id"],
            download_url=self.u_url.get().strip(),
            download_timestamp=time.time(), is_malicious=False)
        tx.do_sign(keys["private"])
        self.u_tx = tx.to_dict(); self.u_blk = self.u_mined = None
        self.u_rejected_reason = ""
        self.u_status_lbl.configure(text="", text_color=C["orange"])
        self._fill_box(self.u_tx_box, self.u_tx, C["user"]); self._u_btns()
        self._log(f"[USER] TX {tx_id} PID={pid} ({uid}) → {entry['name']} v{entry['version']} ✅ хэш легитимен", "user")

    def _u_create_blk(self):
        if not self.u_tx: return
        self.uchain.pending_transactions = [self.u_tx]
        self.u_blk = self.uchain.create_block("Miner-U"); self.u_mined = None
        self._u_btns(); self._log(f"[USER] Блок #{self.u_blk.index} создан", "user")

    def _u_mine(self):
        if not self.u_blk: return
        blk = self.u_blk; self._status("⏳ МАЙНИНГ...", C["orange"])
        self._log(f"[USER] Майнинг блока #{blk.index}...", "muted")
        def _r():
            it = blk.mine(fast=False)
            self.u_mined = blk; self.u_blk = None
            self.after(0, lambda: self._log(f"[USER] ✅ Hash={blk.hash[:18]}... Nonce={blk.nonce} Iter={it}", "green"))
            self.after(0, lambda: self._status("● АКТИВНА", C["green"]))
            self.after(0, self._u_btns)
        threading.Thread(target=_r, daemon=True).start()

    def _u_add(self):
        if not self.u_mined: return
        ok, reason = self.uchain.add_block(self.u_mined)
        if ok:
            self._log(f"[USER] ✅ Блок #{self.u_mined.index} добавлен. Цепь: {len(self.uchain.chain)}", "green")
            self.u_status_lbl.configure(text="✅ Блок принят!", text_color=C["green"])
            self.u_tx = self.u_blk = self.u_mined = None
            self._fill_box(self.u_tx_box, None, C["user"]); self._u_btns(); self._redraw()
        else:
            self.u_rejected_reason = reason
            msg = f"❌ БЛОК ОТКЛОНЁН:\n{reason}"
            self.u_status_lbl.configure(text=msg, text_color=C["red"])
            self._log(f"[USER] ❌ Блок отклонён: {reason}", "red")
            self.u_tx = self.u_blk = self.u_mined = None
            self._fill_box(self.u_tx_box, None, C["user"]); self._u_btns()

    def _u_btns(self):
        self._sbtn(self.btn_u1, True, C["user"])
        self._sbtn(self.btn_u2, bool(self.u_tx and not self.u_blk and not self.u_mined), C["card"])
        self._sbtn(self.btn_u3, bool(self.u_blk), C["purple"])
        self._sbtn(self.btn_u4, bool(self.u_mined), C["green"])

    # ══════════════════════════════════════════════════════════════════════
    #  ЗЛОУМЫШЛЕННИК — логика
    # ══════════════════════════════════════════════════════════════════════
    def _a_sw_pick(self, label: str):
        entry = self._by_label(label)
        if entry:
            self.a_legit_var.set(entry["hash"])

    def _a_create_tx(self):
        entry = self._by_label(self.a_sw.get())
        if not entry:
            self._log("[ATK] Выберите ПО из каталога!", "orange"); return
        
        target_uid = self.a_target_user.get()
        # Ключи всегда атакующего, но UID выбирается любой
        keys  = self.registry.user_keys("attacker")
        
        pid   = "PID-A-" + uuid.uuid4().hex[:6].upper()
        tx_id = "UTX-"   + uuid.uuid4().hex[:8].upper()
        fake_h = self.a_fake_var.get().strip() or rnd_hash()
        
        tx = UserTransaction(tx_id=tx_id, pid=pid, actor="attacker",
            user_id=target_uid, user_public_key=keys["public"],
            software_name=entry["name"], version=entry["version"],
            downloaded_hash=fake_h,          # ← ПОДМЕНЁННЫЙ ХЭШ
            vendor_tx_id=entry["tx_id"],
            download_url="http://evil.malware/payload.exe",
            download_timestamp=time.time(), is_malicious=True)
            
        tx.do_sign(keys["private"])
        self.a_tx = tx.to_dict(); self.a_blk = self.a_mined = None
        self._fill_box(self.a_tx_box, self.a_tx, C["atk"]); self._a_btns()
        self._log(f"[ATK] ☠ TX {tx_id} PID={pid}: UID={target_uid}, хэш ПОДМЕНЁН на {fake_h[:18]}...", "atk")

    def _a_create_blk(self):
        if not self.a_tx: return
        self.uchain.pending_transactions = [self.a_tx]
        self.a_blk = self.uchain.create_block("Attacker", is_attacker=True); self.a_mined = None
        self._a_btns(); self._log(f"[ATK] ☠ Блок #{self.a_blk.index} создан злоумышленником", "atk")

    def _a_mine(self):
        if not self.a_blk: return
        blk = self.a_blk; self._status("⏳ МАЙНИНГ (ATK)...", C["red"])
        self._log(f"[ATK] ☠ Майнинг (>51% мощности, nonce от 50000)...", "atk")
        def _r():
            it = blk.mine(fast=True)    # ← стартует с большого nonce
            self.a_mined = blk; self.a_blk = None
            self.after(0, lambda: self._log(
                f"[ATK] ☠ Смайнен! Hash={blk.hash[:18]}... Nonce={blk.nonce} Iter={it} (стартовал с ~50000)", "atk"))
            self.after(0, lambda: self._status("● АКТИВНА", C["green"]))
            self.after(0, self._a_btns)
        threading.Thread(target=_r, daemon=True).start()

    def _a_add(self):
        if not self.a_mined: return
        ok, reason = self.uchain.add_block(self.a_mined)
        if ok:
            self._log(f"[ATK] ☠ Блок злоумышленника #{self.a_mined.index} ДОБАВЛЕН ПЕРВЫМ в цепь!", "atk")
            self._log("[ATK] ☠ Теперь vendor_tx_id занят. Блок легитимного пользователя будет отклонён.", "orange")
            self.a_tx = self.a_blk = self.a_mined = None
            self._fill_box(self.a_tx_box, None, C["atk"]); self._a_btns(); self._redraw()
        else:
            self._log(f"[ATK] Блок злоумышленника отклонён: {reason}", "red")
            self.a_tx = self.a_blk = self.a_mined = None
            self._fill_box(self.a_tx_box, None, C["atk"]); self._a_btns()

    def _a_btns(self):
        self._sbtn(self.btn_a1, True, C["atk"])
        self._sbtn(self.btn_a2, bool(self.a_tx and not self.a_blk and not self.a_mined), C["card"])
        self._sbtn(self.btn_a3, bool(self.a_blk), C["red"])
        self._sbtn(self.btn_a4, bool(self.a_mined), C["orange"])

    # ══════════════════════════════════════════════════════════════════════
    #  ВАЛИДАЦИЯ
    # ══════════════════════════════════════════════════════════════════════
    def _val_struct(self, ct: str):
        chain = self.vchain if ct == "vendor" else self.uchain
        if not chain.chain:
            self._fill_box(self.val_box, f"Цепь {ct.upper()} пуста.", C["muted"]); return
        errs = chain.validate_chain()
        if errs:
            self._fill_box(self.val_box, f"❌ {ct.upper()}: {len(errs)} ошибок:\n"+"".join(f"  • {e}\n" for e in errs), C["red"])
        else:
            self._fill_box(self.val_box, f"✅ {ct.upper()} цепь валидна. Блоков: {len(chain.chain)}", C["green"])

    def _val_hashes(self):
        if not self.uchain.chain:
            self._fill_box(self.val_box, "User-цепь пуста.", C["muted"]); return
        vidx = self.vchain.all_vendor_txs()
        rows = self.uchain.check_user_hashes(vidx)
        if not rows:
            self._fill_box(self.val_box, "Нет user-транзакций.", C["muted"]); return
        lines = ["=== СВЕРКА ХЭШЕЙ ПО (vendor ↔ user) ===\n"]
        all_ok = True
        for r in rows:
            actor_icon = "☠️ ЗЛОУМЫШЛЕННИК" if r["actor"] == "attacker" else f"👤 {r['user']}"
            if r["status"] == "ok":
                icon = "✅ ХЭШ СОВПАДАЕТ — легитимно"
            elif r["status"] == "attack":
                icon = "🚨 ХЭШ НЕ СОВПАДАЕТ — SSC-АТАКА ЗАФИКСИРОВАНА!"; all_ok = False
            else:
                icon = "❓ Vendor TX не найден"; all_ok = False
            lines.append(
                f"  Блок #{r['block']} | TX: {r['tx_id']} | PID: {r['pid']}\n"
                f"    Актор: {actor_icon}\n"
                f"    ПО: {r['software']} v{r['version']}\n"
                f"    {icon}\n"
            )
        lines.append("─"*44)
        lines.append("✅ Все записи легитимны." if all_ok else "⚠️ В цепи обнаружены подозрительные транзакции!")
        self._fill_box(self.val_box, "\n".join(lines), C["text"])
        self._log("[VAL] Сверка хэшей выполнена", "green" if all_ok else "red")

    # ══════════════════════════════════════════════════════════════════════
    #  Отрисовка цепей
    # ══════════════════════════════════════════════════════════════════════
    def _redraw(self):
        self._draw_chain(self.vsf, self.vchain, C["vendor"])
        self._draw_chain(self.usf, self.uchain,  C["user"])

    def _draw_chain(self, sf, chain: Blockchain, accent: str):
        for w in sf.winfo_children(): w.destroy()
        if not chain.chain:
            ctk.CTkLabel(sf, text="(цепь пуста)", font=MNS, text_color=C["muted"]).pack(pady=20)
            return
        for i, blk in enumerate(chain.chain):
            self._blk_card(sf, blk, accent)
            if i < len(chain.chain)-1:
                ctk.CTkLabel(sf, text="↓", font=("Courier New",13,"bold"), text_color=accent).pack()

    def _blk_card(self, parent, blk: Block, accent: str):
        bc = C["atk"] if blk.is_attacker else accent
        card = ctk.CTkFrame(parent, fg_color=C["card"], border_color=bc, border_width=1, corner_radius=6)
        card.pack(fill="x", pady=3, padx=2)

        hf = ctk.CTkFrame(card, fg_color=bc, corner_radius=4); hf.pack(fill="x", padx=4, pady=4)
        atk = "  ☠ ATTACKER" if blk.is_attacker else ""
        ctk.CTkLabel(hf, text=f"  БЛОК #{blk.index}{atk}  |  {blk.mined_by}",
                     font=("Courier New",9,"bold"), text_color="#fff").pack(side="left", padx=4)
        ctk.CTkLabel(hf, text=datetime.fromtimestamp(blk.timestamp).strftime("%H:%M:%S"),
                     font=("Courier New",8), text_color="#fff").pack(side="right", padx=4)

        for lbl, val in [
            ("Hash",     blk.hash[:32]+"..." if blk.hash else "—"),
            ("PrevHash", blk.previous_hash[:32]+"..."),
            ("Nonce",    str(blk.nonce)),
        ]:
            rf = ctk.CTkFrame(card, fg_color="transparent"); rf.pack(fill="x", padx=6, pady=0)
            ctk.CTkLabel(rf, text=f"{lbl}:", width=64, anchor="w",
                         font=("Courier New",8), text_color=C["muted"]).pack(side="left")
            ctk.CTkLabel(rf, text=val, anchor="w",
                         font=("Courier New",8), text_color=bc).pack(side="left")

        for tx in blk.transactions:
            tx_id = tx.get("tx_id","")
            tf = ctk.CTkFrame(card, fg_color=C["bg"], corner_radius=3); tf.pack(fill="x", padx=6, pady=2)
            if tx_id.startswith("VTX"):
                sw  = tx.get("software_name","?"); ver = tx.get("version","?")
                h   = tx.get("software_hash","?")[:20]
                ctk.CTkLabel(tf, text=f"  📦 VTX {sw} v{ver}  hash:{h}...",
                             font=("Courier New",8), text_color=C["vendor"], anchor="w").pack(fill="x", padx=4, pady=2)
            elif tx_id.startswith("UTX"):
                sw    = tx.get("software_name","?"); ver = tx.get("version","?")
                h     = tx.get("downloaded_hash","?")[:20]
                evil  = tx.get("is_malicious", False) or tx.get("actor","") == "attacker"
                pid   = tx.get("pid","?")
                actor = tx.get("actor","?")
                tc    = C["atk"] if evil else C["user"]
                icon  = "☠ ПОДДЕЛКА" if evil else "✓ легит."
                ctk.CTkLabel(tf,
                    text=f"  {'☠' if evil else '👤'} UTX [{actor}] PID:{pid}\n"
                         f"     {sw} v{ver}  hash:{h}...\n"
                         f"     {icon}",
                    font=("Courier New",8), text_color=tc, anchor="w",
                    justify="left").pack(fill="x", padx=4, pady=2)

    # ══════════════════════════════════════════════════════════════════════
    #  Вспомогательные
    # ══════════════════════════════════════════════════════════════════════
    def _by_label(self, label: str) -> Optional[dict]:
        for e in self.catalog.values():
            if e["label"] == label: return e
        return None

    def _refresh_sw_combos(self):
        labels = [e["label"] for e in self.catalog.values()]
        if labels:
            for cmb in (self.u_sw, self.a_sw):
                cmb.configure(values=labels); cmb.set(labels[-1])
            self._u_sw_pick(labels[-1])
            self._a_sw_pick(labels[-1])

    def _sbtn(self, btn, on: bool, color: str):
        if on:
            btn.configure(state="normal", fg_color=color, hover_color=dk(color), text_color="#fff")
        else:
            btn.configure(state="disabled", fg_color=C["border"], hover_color=C["border"], text_color=C["muted"])

    def _sec(self, p, t):
        f = ctk.CTkFrame(p, fg_color="transparent"); f.pack(fill="x", padx=4, pady=(10,2))
        ctk.CTkLabel(f, text=t, font=("Courier New",10,"bold"), text_color=C["muted"]).pack(anchor="w", padx=6)
        ctk.CTkFrame(f, fg_color=C["border"], height=1).pack(fill="x", padx=6, pady=2)

    def _ent(self, p, label, default="") -> ctk.CTkEntry:
        ctk.CTkLabel(p, text=label, font=MNS, text_color=C["muted"]).pack(anchor="w", padx=10, pady=(4,0))
        e = ctk.CTkEntry(p, font=MNS, fg_color=C["card"], border_color=C["border"], text_color=C["text"])
        e.insert(0, default); e.pack(fill="x", padx=8, pady=2); return e

    def _cmb(self, p, label, values) -> ctk.CTkComboBox:
        ctk.CTkLabel(p, text=label, font=MNS, text_color=C["muted"]).pack(anchor="w", padx=10, pady=(4,0))
        c = ctk.CTkComboBox(p, values=values, font=MNS, fg_color=C["card"],
                             border_color=C["border"], button_color=C["border"],
                             dropdown_fg_color=C["panel"], text_color=C["text"])
        c.set(values[0]); c.pack(fill="x", padx=8, pady=2); return c

    def _btn(self, p, text, color, cmd) -> ctk.CTkButton:
        b = ctk.CTkButton(p, text=text, fg_color=color, hover_color=dk(color),
                           font=MNB, text_color="#fff", height=36, command=cmd)
        b.pack(fill="x", padx=8, pady=3); return b

    def _txbox(self, p, h, color) -> ctk.CTkTextbox:
        tb = ctk.CTkTextbox(p, height=h, font=MNS, fg_color=C["card"],
                             text_color=color, border_color=C["border"], border_width=1)
        tb.pack(fill="x", padx=8, pady=4); tb.configure(state="disabled"); return tb

    def _fill_box(self, box: ctk.CTkTextbox, data, color: str):
        box.configure(state="normal", text_color=color); box.delete("1.0","end")
        if isinstance(data, dict):
            for k, v in data.items():
                if k in ("vendor_public_key","user_public_key","signature"):
                    v = str(v)[:28]+"..."
                box.insert("end", f"{k}: {v}\n")
        elif isinstance(data, str):
            box.insert("end", data)
        box.configure(state="disabled")

    def _log(self, msg: str, tag: str = "text"):
        def _d():
            self.log_w.configure(state="normal")
            self.log_w.insert("end", f"[{ts()}] {msg}\n", tag)
            self.log_w.see("end"); self.log_w.configure(state="disabled")
        self.after(0, _d)

    def _log_clear(self):
        self.log_w.configure(state="normal"); self.log_w.delete("1.0","end")
        self.log_w.configure(state="disabled")

    def _status(self, text: str, color: str):
        self.after(0, lambda: self.lbl_st.configure(text=text, text_color=color))


# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    app = App()
    app.mainloop()
