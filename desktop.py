#!/usr/bin/env python3
"""Elegant Windows desktop interface for the SCAN reconnaissance toolkit."""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from lib.subfinder import _locate_subfinder


APP_DIR = Path(__file__).resolve().parent
SCAN_SCRIPT = APP_DIR / "scan.py"
RESULTS_DIR = APP_DIR / "results"


COLORS = {
    "canvas": "#DDDDD7",
    "surface": "#F5F2EA",
    "surface_alt": "#E9E8E2",
    "well": "#E1E2DD",
    "ink": "#202B26",
    "muted": "#65706A",
    "quiet": "#858E89",
    "line": "#BABCB7",
    "edge_light": "#FFFFFF",
    "edge_dark": "#A6AAA5",
    "shadow": "#C0C1BC",
    "accent": "#346B58",
    "accent_hover": "#2A5C4A",
    "accent_soft": "#D3DED8",
    "amber": "#9A6A24",
    "amber_soft": "#F7EDD9",
    "red": "#A34942",
    "red_soft": "#F7E8E6",
    "blue": "#49677B",
    "blue_soft": "#E8EEF2",
}


MODES = {
    "subs": {
        "nav": "Subdomains",
        "eyebrow": "DISCOVERY",
        "title": "Subdomain discovery",
        "description": "Map public-facing hosts quickly, then verify which ones respond.",
        "target_label": "Domain",
        "placeholder": "example.com",
    },
    "endpoints": {
        "nav": "API endpoints",
        "eyebrow": "APPLICATION",
        "title": "API endpoint discovery",
        "description": "Inspect specifications, common paths, responses, and JavaScript references.",
        "target_label": "Base URL",
        "placeholder": "https://api.example.com",
    },
    "full": {
        "nav": "Full reconnaissance",
        "eyebrow": "COMBINED",
        "title": "Full reconnaissance",
        "description": "Discover hosts first, then inspect endpoints across the selected scope.",
        "target_label": "Domain",
        "placeholder": "example.com",
    },
    "crawl": {
        "nav": "Web crawler",
        "eyebrow": "CONTENT",
        "title": "Web application crawl",
        "description": "Follow real same-origin links and organize pages, parameters, and assets.",
        "target_label": "Starting URL",
        "placeholder": "https://example.com",
    },
}


ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def enable_windows_dpi_awareness() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


class ScanDesktop(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Scan — Reconnaissance Workspace")
        self.configure(bg=COLORS["canvas"])
        self.minsize(1080, 700)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.report_callback_exception = self._report_callback_exception

        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        width = min(1380, max(1080, screen_w - 180))
        height = min(900, max(700, screen_h - 160))
        x = max(0, (screen_w - width) // 2)
        y = max(0, (screen_h - height) // 2)
        self.geometry(f"{width}x{height}+{x}+{y}")

        self.mode = "subs"
        self.nav_buttons: dict[str, tk.Button] = {}
        self.process: subprocess.Popen[str] | None = None
        self.scan_active = False
        self.setup_process: subprocess.Popen[str] | None = None
        self.setup_active = False
        self.process_lock = threading.Lock()
        self.events: queue.Queue[tuple] = queue.Queue()
        self.started_at = 0.0
        self.result_path: Path | None = None
        self.result_rows: list[dict] = []
        self.cancel_requested = False

        self._create_variables()
        self._configure_styles()
        self._build_layout()
        self._select_mode("subs")
        self.after(80, self._drain_events)

    # ------------------------------------------------------------------
    # Setup
    # ------------------------------------------------------------------

    def _create_variables(self) -> None:
        self.target_var = tk.StringVar()
        self.output_var = tk.StringVar()
        self.authorized_var = tk.BooleanVar(value=False)

        self.timeout_var = tk.StringVar(value="30")
        self.source_threads_var = tk.StringVar(value="6")
        self.subfinder_timeout_var = tk.StringVar(value="120")
        self.live_only_var = tk.BooleanVar(value=False)
        self.live_timeout_var = tk.StringVar(value="4")
        self.workers_var = tk.StringVar(value="100")
        self.all_sources_var = tk.BooleanVar(value=False)

        self.min_priority_var = tk.StringVar(value="0")
        self.methods_var = tk.StringVar(value="")
        self.max_hosts_var = tk.StringVar(value="10")

        self.max_pages_var = tk.StringVar(value="300")
        self.max_depth_var = tk.StringVar(value="6")
        self.delay_var = tk.StringVar(value="0.05")
        self.no_assets_var = tk.BooleanVar(value=False)
        self.params_only_var = tk.BooleanVar(value=False)

        self.search_var = tk.StringVar()
        self.search_var.trace_add("write", lambda *_: self._render_results())

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        style.theme_use("clam")

        style.configure("App.TFrame", background=COLORS["canvas"])
        style.configure("Surface.TFrame", background=COLORS["surface"])
        style.configure("Quiet.TFrame", background=COLORS["surface_alt"])
        style.configure(
            "Title.TLabel",
            background=COLORS["canvas"],
            foreground=COLORS["ink"],
            font=("Segoe UI Semibold", 22),
        )
        style.configure(
            "Eyebrow.TLabel",
            background=COLORS["canvas"],
            foreground=COLORS["accent"],
            font=("Segoe UI Semibold", 9),
        )
        style.configure(
            "Body.TLabel",
            background=COLORS["canvas"],
            foreground=COLORS["muted"],
            font=("Segoe UI", 10),
        )
        style.configure(
            "CardTitle.TLabel",
            background=COLORS["surface"],
            foreground=COLORS["ink"],
            font=("Segoe UI Semibold", 11),
        )
        style.configure(
            "CardBody.TLabel",
            background=COLORS["surface"],
            foreground=COLORS["muted"],
            font=("Segoe UI", 9),
        )
        style.configure(
            "Field.TLabel",
            background=COLORS["surface"],
            foreground=COLORS["ink"],
            font=("Segoe UI Semibold", 9),
        )
        style.configure(
            "Hint.TLabel",
            background=COLORS["surface"],
            foreground=COLORS["quiet"],
            font=("Segoe UI", 8),
        )
        style.configure(
            "TEntry",
            fieldbackground=COLORS["well"],
            foreground=COLORS["ink"],
            bordercolor=COLORS["edge_dark"],
            lightcolor=COLORS["edge_dark"],
            darkcolor=COLORS["edge_light"],
            relief="sunken",
            borderwidth=1,
            padding=(10, 8),
        )
        style.map("TEntry", bordercolor=[("focus", COLORS["accent"])])
        style.configure(
            "TCheckbutton",
            background=COLORS["surface"],
            foreground=COLORS["ink"],
            font=("Segoe UI", 9),
        )
        style.map("TCheckbutton", background=[("active", COLORS["surface"])])
        style.configure(
            "Primary.TButton",
            background=COLORS["accent"],
            foreground="#FFFFFF",
            borderwidth=1,
            relief="raised",
            lightcolor="#72A08F",
            darkcolor="#1E493A",
            padding=(19, 11),
            font=("Segoe UI Semibold", 10),
        )
        style.map(
            "Primary.TButton",
            background=[("active", COLORS["accent_hover"]), ("disabled", "#9CB2AA")],
            relief=[("pressed", "sunken"), ("!pressed", "raised")],
        )
        style.configure(
            "Secondary.TButton",
            background=COLORS["surface"],
            foreground=COLORS["ink"],
            bordercolor=COLORS["edge_dark"],
            lightcolor=COLORS["edge_light"],
            darkcolor=COLORS["edge_dark"],
            borderwidth=1,
            relief="raised",
            padding=(14, 9),
            font=("Segoe UI Semibold", 9),
        )
        style.map(
            "Secondary.TButton",
            background=[("active", COLORS["surface_alt"])],
            relief=[("pressed", "sunken"), ("!pressed", "raised")],
        )
        style.configure(
            "Danger.TButton",
            background=COLORS["red_soft"],
            foreground=COLORS["red"],
            borderwidth=1,
            relief="raised",
            lightcolor="#FFF5F3",
            darkcolor="#B98B86",
            padding=(14, 9),
            font=("Segoe UI Semibold", 9),
        )
        style.configure(
            "Scan.Horizontal.TProgressbar",
            background=COLORS["accent"],
            troughcolor=COLORS["accent_soft"],
            borderwidth=0,
            thickness=3,
        )
        style.configure(
            "TNotebook",
            background=COLORS["surface"],
            borderwidth=1,
            relief="sunken",
            lightcolor=COLORS["edge_dark"],
            darkcolor=COLORS["edge_light"],
        )
        style.configure(
            "TNotebook.Tab",
            background=COLORS["surface"],
            foreground=COLORS["muted"],
            padding=(18, 11),
            font=("Segoe UI Semibold", 9),
            borderwidth=1,
            relief="raised",
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", COLORS["surface"])],
            foreground=[("selected", COLORS["accent"])],
            relief=[("selected", "sunken"), ("!selected", "raised")],
        )
        style.configure(
            "Treeview",
            background=COLORS["surface"],
            fieldbackground=COLORS["surface"],
            foreground=COLORS["ink"],
            rowheight=31,
            borderwidth=1,
            relief="sunken",
            font=("Segoe UI", 9),
        )
        style.configure(
            "Treeview.Heading",
            background=COLORS["surface_alt"],
            foreground=COLORS["muted"],
            relief="flat",
            font=("Segoe UI Semibold", 8),
            padding=(8, 8),
        )
        style.map("Treeview", background=[("selected", COLORS["accent_soft"])], foreground=[("selected", COLORS["ink"])])

    def _build_layout(self) -> None:
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main()

    def _build_sidebar(self) -> None:
        sidebar = tk.Frame(
            self,
            bg=COLORS["surface"],
            width=238,
            relief="raised",
            bd=1,
            highlightbackground=COLORS["edge_light"],
            highlightthickness=1,
        )
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_rowconfigure(2, weight=1)

        brand = tk.Frame(sidebar, bg=COLORS["surface"])
        brand.grid(row=0, column=0, sticky="ew", padx=24, pady=(28, 24))

        mark = tk.Frame(brand, bg=COLORS["accent"], width=38, height=38, relief="raised", bd=1)
        mark.pack(side="left")
        mark.pack_propagate(False)
        tk.Label(mark, text="S", bg=COLORS["accent"], fg="white", font=("Segoe UI Semibold", 16)).pack(expand=True)

        names = tk.Frame(brand, bg=COLORS["surface"])
        names.pack(side="left", padx=(11, 0))
        tk.Label(names, text="SCAN", bg=COLORS["surface"], fg=COLORS["ink"], font=("Segoe UI Semibold", 13)).pack(anchor="w")
        tk.Label(names, text="Reconnaissance", bg=COLORS["surface"], fg=COLORS["quiet"], font=("Segoe UI", 8)).pack(anchor="w")

        tk.Label(
            sidebar,
            text="WORKSPACE",
            bg=COLORS["surface"],
            fg=COLORS["quiet"],
            font=("Segoe UI Semibold", 8),
        ).grid(row=1, column=0, sticky="w", padx=25, pady=(4, 9))

        nav = tk.Frame(sidebar, bg=COLORS["surface"])
        nav.grid(row=2, column=0, sticky="new", padx=12)
        for mode, meta in MODES.items():
            button = tk.Button(
                nav,
                text=meta["nav"],
                command=lambda value=mode: self._select_mode(value),
                anchor="w",
                relief="flat",
                bd=0,
                padx=14,
                pady=11,
                bg=COLORS["surface"],
                fg=COLORS["muted"],
                activebackground=COLORS["surface_alt"],
                activeforeground=COLORS["ink"],
                font=("Segoe UI Semibold", 9),
                cursor="hand2",
            )
            button.pack(fill="x", pady=2)
            self.nav_buttons[mode] = button

        self._build_engine_panel(sidebar)

        note = tk.Frame(sidebar, bg=COLORS["surface_alt"], relief="sunken", bd=1, highlightbackground=COLORS["edge_light"], highlightthickness=1)
        note.grid(row=4, column=0, sticky="sew", padx=18, pady=(0, 18))
        tk.Label(note, text="Responsible use", bg=COLORS["surface_alt"], fg=COLORS["ink"], font=("Segoe UI Semibold", 9)).pack(anchor="w", padx=13, pady=(12, 4))
        tk.Label(
            note,
            text="Only test systems you own or have written permission to assess.",
            wraplength=175,
            justify="left",
            bg=COLORS["surface_alt"],
            fg=COLORS["muted"],
            font=("Segoe UI", 8),
        ).pack(anchor="w", padx=13, pady=(0, 12))

    def _build_engine_panel(self, sidebar: tk.Frame) -> None:
        panel = tk.Frame(
            sidebar,
            bg=COLORS["surface_alt"],
            relief="raised",
            bd=1,
            highlightbackground=COLORS["edge_light"],
            highlightthickness=1,
        )
        panel.grid(row=3, column=0, sticky="sew", padx=18, pady=(8, 10))
        tk.Label(
            panel,
            text="Discovery engine",
            bg=COLORS["surface_alt"],
            fg=COLORS["ink"],
            font=("Segoe UI Semibold", 9),
        ).pack(anchor="w", padx=12, pady=(10, 2))
        self.engine_status_label = tk.Label(
            panel,
            text="Checking…",
            bg=COLORS["surface_alt"],
            fg=COLORS["muted"],
            font=("Segoe UI", 8),
        )
        self.engine_status_label.pack(anchor="w", padx=12)
        self.engine_button = tk.Button(
            panel,
            text="Install extended engine",
            command=self._install_subfinder,
            relief="raised",
            bd=1,
            bg=COLORS["surface"],
            fg=COLORS["ink"],
            activebackground=COLORS["accent_soft"],
            activeforeground=COLORS["accent"],
            font=("Segoe UI Semibold", 8),
            cursor="hand2",
            padx=8,
            pady=5,
        )
        self.engine_button.pack(fill="x", padx=10, pady=(8, 10))
        self._refresh_engine_status()

    def _build_main(self) -> None:
        main = ttk.Frame(self, style="App.TFrame", padding=(30, 25, 30, 22))
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(1, weight=1)

        header = ttk.Frame(main, style="App.TFrame")
        header.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        header.grid_columnconfigure(0, weight=1)

        heading = ttk.Frame(header, style="App.TFrame")
        heading.grid(row=0, column=0, sticky="w")
        self.eyebrow_label = ttk.Label(heading, style="Eyebrow.TLabel")
        self.eyebrow_label.pack(anchor="w")
        self.title_label = ttk.Label(heading, style="Title.TLabel")
        self.title_label.pack(anchor="w", pady=(4, 3))
        self.description_label = ttk.Label(heading, style="Body.TLabel")
        self.description_label.pack(anchor="w")

        actions = ttk.Frame(header, style="App.TFrame")
        actions.grid(row=0, column=1, sticky="e")
        self.cancel_button = ttk.Button(actions, text="Cancel", style="Danger.TButton", command=self._cancel_scan, state="disabled")
        self.cancel_button.pack(side="left", padx=(0, 8))
        self.run_button = ttk.Button(actions, text="Run scan", style="Primary.TButton", command=self._start_scan)
        self.run_button.pack(side="left")

        body = ttk.Frame(main, style="App.TFrame")
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_columnconfigure(0, minsize=350)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._build_config_card(body)
        self._build_workspace_card(body)

        footer = ttk.Frame(main, style="App.TFrame")
        footer.grid(row=2, column=0, sticky="ew", pady=(13, 0))
        footer.grid_columnconfigure(1, weight=1)
        self.status_dot = tk.Label(footer, text="●", bg=COLORS["canvas"], fg=COLORS["quiet"], font=("Segoe UI", 8))
        self.status_dot.grid(row=0, column=0, padx=(0, 7))
        self.status_label = tk.Label(footer, text="Ready", bg=COLORS["canvas"], fg=COLORS["muted"], font=("Segoe UI", 9))
        self.status_label.grid(row=0, column=1, sticky="w")
        self.elapsed_label = tk.Label(footer, text="", bg=COLORS["canvas"], fg=COLORS["quiet"], font=("Segoe UI", 9))
        self.elapsed_label.grid(row=0, column=2, sticky="e")

    def _build_config_card(self, parent: ttk.Frame) -> None:
        card = tk.Frame(
            parent,
            bg=COLORS["surface"],
            relief="raised",
            bd=1,
            highlightbackground=COLORS["edge_light"],
            highlightthickness=1,
        )
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 16))
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)

        head = ttk.Frame(card, style="Surface.TFrame", padding=(20, 17, 20, 14))
        head.grid(row=0, column=0, sticky="ew")
        ttk.Label(head, text="Scan settings", style="CardTitle.TLabel").pack(anchor="w")
        ttk.Label(head, text="Configure the target and request budget.", style="CardBody.TLabel").pack(anchor="w", pady=(3, 0))

        self.form_canvas = tk.Canvas(card, bg=COLORS["surface"], highlightthickness=0, bd=0)
        self.form_canvas.grid(row=1, column=0, sticky="nsew")
        form_scroll = ttk.Scrollbar(card, orient="vertical", command=self.form_canvas.yview)
        form_scroll.grid(row=1, column=1, sticky="ns")
        self.form_canvas.configure(yscrollcommand=form_scroll.set)

        self.form = ttk.Frame(self.form_canvas, style="Surface.TFrame", padding=(20, 8, 20, 20))
        self.form_window = self.form_canvas.create_window((0, 0), window=self.form, anchor="nw")
        self.form.bind("<Configure>", lambda _e: self.form_canvas.configure(scrollregion=self.form_canvas.bbox("all")))
        self.form_canvas.bind("<Configure>", lambda e: self.form_canvas.itemconfigure(self.form_window, width=e.width))

    def _build_workspace_card(self, parent: ttk.Frame) -> None:
        card = tk.Frame(
            parent,
            bg=COLORS["surface"],
            relief="raised",
            bd=1,
            highlightbackground=COLORS["edge_light"],
            highlightthickness=1,
        )
        card.grid(row=0, column=1, sticky="nsew")
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(2, weight=1)

        metrics = ttk.Frame(card, style="Surface.TFrame", padding=(18, 15))
        metrics.grid(row=0, column=0, sticky="ew")
        for col in range(3):
            metrics.grid_columnconfigure(col, weight=1)

        self.metric_values: dict[str, tk.Label] = {}
        self.metric_labels: dict[str, tk.Label] = {}
        for col, (key, label) in enumerate((("results", "RESULTS"), ("priority", "HIGH PRIORITY"), ("duration", "DURATION"))):
            cell = tk.Frame(metrics, bg=COLORS["surface_alt"], relief="sunken", bd=1, padx=10, pady=6)
            cell.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 18, 0))
            metric_label = tk.Label(cell, text=label, bg=COLORS["surface_alt"], fg=COLORS["quiet"], font=("Segoe UI Semibold", 8))
            metric_label.pack(anchor="w")
            value = tk.Label(cell, text="—", bg=COLORS["surface_alt"], fg=COLORS["ink"], font=("Segoe UI Semibold", 15))
            value.pack(anchor="w", pady=(2, 0))
            self.metric_labels[key] = metric_label
            self.metric_values[key] = value

        self.progress = ttk.Progressbar(card, style="Scan.Horizontal.TProgressbar", mode="indeterminate")
        self.progress.grid(row=1, column=0, sticky="ew")
        self.progress.grid_remove()

        self.notebook = ttk.Notebook(card)
        self.notebook.grid(row=2, column=0, sticky="nsew")

        self.activity_tab = ttk.Frame(self.notebook, style="Surface.TFrame")
        self.results_tab = ttk.Frame(self.notebook, style="Surface.TFrame")
        self.notebook.add(self.activity_tab, text="Activity")
        self.notebook.add(self.results_tab, text="Results")
        self._build_activity_tab()
        self._build_results_tab()

    def _build_activity_tab(self) -> None:
        self.activity_tab.grid_columnconfigure(0, weight=1)
        self.activity_tab.grid_rowconfigure(1, weight=1)

        tools = ttk.Frame(self.activity_tab, style="Surface.TFrame", padding=(18, 13, 18, 8))
        tools.grid(row=0, column=0, sticky="ew")
        ttk.Label(tools, text="Live activity", style="CardTitle.TLabel").pack(side="left")
        ttk.Button(tools, text="Clear", style="Secondary.TButton", command=self._clear_log).pack(side="right")

        log_frame = tk.Frame(self.activity_tab, bg=COLORS["surface"], padx=18, pady=10)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.grid_columnconfigure(0, weight=1)
        log_frame.grid_rowconfigure(0, weight=1)

        self.log = tk.Text(
            log_frame,
            wrap="word",
            state="disabled",
            relief="sunken",
            bd=1,
            bg=COLORS["well"],
            fg=COLORS["ink"],
            selectbackground=COLORS["accent_soft"],
            insertbackground=COLORS["ink"],
            font=("Cascadia Mono", 9),
            padx=15,
            pady=13,
            spacing1=2,
            spacing3=2,
        )
        self.log.grid(row=0, column=0, sticky="nsew")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.log.configure(yscrollcommand=log_scroll.set)
        self.log.tag_configure("muted", foreground=COLORS["muted"])
        self.log.tag_configure("success", foreground=COLORS["accent"])
        self.log.tag_configure("warning", foreground=COLORS["amber"])
        self.log.tag_configure("error", foreground=COLORS["red"])
        self.log.tag_configure("heading", foreground=COLORS["blue"], font=("Cascadia Mono", 9, "bold"))

    def _build_results_tab(self) -> None:
        self.results_tab.grid_columnconfigure(0, weight=1)
        self.results_tab.grid_rowconfigure(1, weight=1)

        tools = ttk.Frame(self.results_tab, style="Surface.TFrame", padding=(18, 13, 18, 8))
        tools.grid(row=0, column=0, sticky="ew")
        tools.grid_columnconfigure(1, weight=1)
        ttk.Label(tools, text="Findings", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        search = ttk.Entry(tools, textvariable=self.search_var)
        search.grid(row=0, column=1, sticky="e", padx=(20, 8), ipadx=45)
        ttk.Button(tools, text="Copy", style="Secondary.TButton", command=self._copy_selected).grid(row=0, column=2, padx=(0, 7))
        ttk.Button(tools, text="Open folder", style="Secondary.TButton", command=self._open_results_folder).grid(row=0, column=3)

        table_frame = tk.Frame(self.results_tab, bg=COLORS["surface"], padx=18, pady=10)
        table_frame.grid(row=1, column=0, sticky="nsew")
        table_frame.grid_columnconfigure(0, weight=1)
        table_frame.grid_rowconfigure(0, weight=1)

        self.results_tree = ttk.Treeview(table_frame, show="headings")
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        y_scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.results_tree.yview)
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll = ttk.Scrollbar(table_frame, orient="horizontal", command=self.results_tree.xview)
        x_scroll.grid(row=1, column=0, sticky="ew")
        self.results_tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        self.results_tree.tag_configure("high", foreground=COLORS["red"])
        self.results_tree.tag_configure("medium", foreground=COLORS["amber"])
        self.results_tree.tag_configure("good", foreground=COLORS["accent"])
        self.results_tree.bind("<Double-1>", lambda _event: self._copy_selected())

        self.empty_results = tk.Label(
            table_frame,
            text="Results will appear here after a scan.",
            bg=COLORS["surface"],
            fg=COLORS["quiet"],
            font=("Segoe UI", 10),
        )
        self.empty_results.place(relx=0.5, rely=0.45, anchor="center")

    # ------------------------------------------------------------------
    # Dynamic form
    # ------------------------------------------------------------------

    def _select_mode(self, mode: str) -> None:
        if self.scan_active:
            return
        self.mode = mode
        meta = MODES[mode]
        self.eyebrow_label.configure(text=meta["eyebrow"])
        self.title_label.configure(text=meta["title"])
        self.description_label.configure(text=meta["description"])
        middle_metric = "RESPONSIVE" if mode == "subs" else "ERRORS" if mode == "crawl" else "HIGH PRIORITY"
        self.metric_labels["priority"].configure(text=middle_metric)
        self.target_var.set("")
        self.output_var.set("")
        self.authorized_var.set(False)
        self.timeout_var.set("30" if mode == "subs" else "10")
        self.live_only_var.set(mode == "full")

        for name, button in self.nav_buttons.items():
            selected = name == mode
            button.configure(
                bg=COLORS["accent_soft"] if selected else COLORS["surface"],
                fg=COLORS["accent"] if selected else COLORS["muted"],
                relief="sunken" if selected else "flat",
                bd=1 if selected else 0,
            )

        self._render_form()
        self._reset_results()
        self._clear_log()
        self._append_log("Ready when you are.\n", "heading")
        self._append_log("Configure the target, confirm authorization, then run the scan.\n", "muted")
        self._set_status("Ready", "idle")

    def _render_form(self) -> None:
        for child in self.form.winfo_children():
            child.destroy()

        meta = MODES[self.mode]
        self._add_field(meta["target_label"], self.target_var, meta["placeholder"])

        if self.mode in ("subs", "full"):
            self._add_section("Discovery")
            self._add_pair(
                ("Source workers", self.source_threads_var, "1–8"),
                ("Source timeout", self.timeout_var, "Seconds"),
            )
            self._add_field("Subfinder time limit", self.subfinder_timeout_var, "Seconds", compact=True)
            self._add_check("Use every Subfinder provider", self.all_sources_var, "More coverage, but noticeably slower.")
            self._add_section("Live verification")
            self._add_check(
                "Return live hosts only",
                self.live_only_var,
                "Filters out DNS-only, firewalled, slow, and historical hosts. Leave off for complete discovery.",
            )
            self._add_pair(
                ("Workers", self.workers_var, "1–200"),
                ("Probe timeout", self.live_timeout_var, "Seconds"),
            )
            if self.mode == "full":
                self._add_section("Endpoint phase")
                self._add_field("Maximum hosts", self.max_hosts_var, "10", compact=True)
                self._add_pair(
                    ("Minimum priority", self.min_priority_var, "0–100"),
                    ("Methods", self.methods_var, "GET,POST"),
                )

        elif self.mode == "endpoints":
            self._add_section("Discovery")
            self._add_pair(
                ("Request timeout", self.timeout_var, "Seconds"),
                ("Minimum priority", self.min_priority_var, "0–100"),
            )
            self._add_field("HTTP methods", self.methods_var, "Optional: GET,POST,DELETE")

        elif self.mode == "crawl":
            self._add_section("Crawl limits")
            self._add_pair(
                ("Maximum pages", self.max_pages_var, "300"),
                ("Maximum depth", self.max_depth_var, "6"),
            )
            self._add_pair(
                ("Request timeout", self.timeout_var, "Seconds"),
                ("Request delay", self.delay_var, "0.05"),
            )
            self._add_check("Hide static assets", self.no_assets_var, "Exclude images, stylesheets, and scripts from output.")
            self._add_check("Parameter URLs only", self.params_only_var, "Show only URLs containing query parameters.")

        self._add_section("Output")
        self._add_output_field()
        self._add_check(
            "I am authorized to scan this target",
            self.authorized_var,
            "Required before the scan can begin.",
        )

        self.form_canvas.yview_moveto(0)

    def _add_section(self, text: str) -> None:
        frame = ttk.Frame(self.form, style="Surface.TFrame")
        frame.pack(fill="x", pady=(17, 8))
        ttk.Label(frame, text=text.upper(), style="Hint.TLabel").pack(side="left")
        ttk.Separator(frame, orient="horizontal").pack(side="left", fill="x", expand=True, padx=(10, 0))

    def _add_field(self, label: str, variable: tk.Variable, hint: str = "", compact: bool = False) -> ttk.Entry:
        wrap = ttk.Frame(self.form, style="Surface.TFrame")
        wrap.pack(fill="x", pady=(0, 11))
        ttk.Label(wrap, text=label, style="Field.TLabel").pack(anchor="w", pady=(0, 5))
        entry = ttk.Entry(wrap, textvariable=variable)
        entry.pack(fill="x")
        if hint:
            ttk.Label(wrap, text=hint, style="Hint.TLabel").pack(anchor="w", pady=(4, 0))
        return entry

    def _add_pair(self, left: tuple, right: tuple) -> None:
        row = ttk.Frame(self.form, style="Surface.TFrame")
        row.pack(fill="x", pady=(0, 11))
        row.grid_columnconfigure(0, weight=1)
        row.grid_columnconfigure(1, weight=1)
        for col, (label, variable, hint) in enumerate((left, right)):
            item = ttk.Frame(row, style="Surface.TFrame")
            item.grid(row=0, column=col, sticky="ew", padx=(0, 6) if col == 0 else (6, 0))
            ttk.Label(item, text=label, style="Field.TLabel").pack(anchor="w", pady=(0, 5))
            ttk.Entry(item, textvariable=variable).pack(fill="x")
            ttk.Label(item, text=hint, style="Hint.TLabel").pack(anchor="w", pady=(4, 0))

    def _add_check(self, label: str, variable: tk.BooleanVar, hint: str = "") -> None:
        wrap = ttk.Frame(self.form, style="Surface.TFrame")
        wrap.pack(fill="x", pady=(1, 10))
        ttk.Checkbutton(wrap, text=label, variable=variable).pack(anchor="w")
        if hint:
            ttk.Label(wrap, text=hint, style="Hint.TLabel", wraplength=295).pack(anchor="w", padx=(23, 0), pady=(2, 0))

    def _add_output_field(self) -> None:
        wrap = ttk.Frame(self.form, style="Surface.TFrame")
        wrap.pack(fill="x", pady=(0, 11))
        ttk.Label(wrap, text="Result file", style="Field.TLabel").pack(anchor="w", pady=(0, 5))
        row = ttk.Frame(wrap, style="Surface.TFrame")
        row.pack(fill="x")
        row.grid_columnconfigure(0, weight=1)
        ttk.Entry(row, textvariable=self.output_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(row, text="Choose", style="Secondary.TButton", command=self._choose_output).grid(row=0, column=1, padx=(7, 0))
        ttk.Label(wrap, text="Leave blank to save automatically in the results folder.", style="Hint.TLabel").pack(anchor="w", pady=(4, 0))

    # ------------------------------------------------------------------
    # Scan execution
    # ------------------------------------------------------------------

    def _start_scan(self) -> None:
        try:
            command, result_path = self._build_command()
        except ValueError as exc:
            messagebox.showerror("Check scan settings", str(exc), parent=self)
            return

        self.result_path = result_path
        self.cancel_requested = False
        self.scan_active = True
        self.started_at = time.monotonic()
        self._reset_results()
        self._clear_log()
        self.notebook.select(self.activity_tab)
        self._append_log(f"Starting {MODES[self.mode]['title'].lower()}\n", "heading")
        self._append_log(f"Target: {self.target_var.get().strip()}\n", "muted")
        self._append_log(f"Results: {result_path}\n\n", "muted")

        self.run_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.progress.grid()
        self.progress.start(12)
        self._set_navigation_enabled(False)
        self._set_status("Scan in progress", "running")
        self._update_elapsed()

        thread = threading.Thread(target=self._run_process, args=(command,), daemon=True)
        thread.start()

    def _build_command(self) -> tuple[list[str], Path]:
        target = self.target_var.get().strip()
        if not target:
            raise ValueError("Enter a target before starting the scan.")
        if not self.authorized_var.get():
            raise ValueError("Confirm that you are authorized to scan this target.")
        if self.mode in ("subs", "full"):
            if "://" in target or "/" in target or not re.fullmatch(r"[A-Za-z0-9.-]+", target):
                raise ValueError("Enter a domain such as example.com, without a scheme or path.")

        timeout = self._int_value(self.timeout_var, "Request timeout", 1, 600)
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        output_text = self.output_var.get().strip()
        if output_text:
            result_path = Path(output_text).expanduser().resolve()
        else:
            RESULTS_DIR.mkdir(parents=True, exist_ok=True)
            safe_target = re.sub(r"[^A-Za-z0-9.-]+", "-", target).strip("-")[:45] or "target"
            result_path = RESULTS_DIR / f"{self.mode}-{safe_target}-{timestamp}.json"
            self.output_var.set(str(result_path))
        result_path.parent.mkdir(parents=True, exist_ok=True)

        command = [
            sys.executable,
            str(SCAN_SCRIPT),
            "--no-banner",
            self.mode,
        ]
        if self.mode in ("subs", "full"):
            command += ["-d", target, "--timeout", str(timeout)]
            command += ["--source-threads", str(self._int_value(self.source_threads_var, "Source workers", 1, 8))]
            command += ["--subfinder-timeout", str(self._int_value(self.subfinder_timeout_var, "Subfinder time limit", 1, 3600))]
            if self.all_sources_var.get():
                command.append("--all-sources")
            if self.live_only_var.get():
                command += [
                    "--live-only",
                    "--live-threads",
                    str(self._int_value(self.workers_var, "Workers", 1, 200)),
                    "--live-timeout",
                    str(self._int_value(self.live_timeout_var, "Probe timeout", 1, 120)),
                ]
            if self.mode == "full":
                command += ["--max-hosts", str(self._int_value(self.max_hosts_var, "Maximum hosts", 1, 1000))]
                command += ["--min-priority", str(self._int_value(self.min_priority_var, "Minimum priority", 0, 100))]
                if self.methods_var.get().strip():
                    command += ["--methods", self.methods_var.get().strip()]

        elif self.mode == "endpoints":
            command += ["-u", target, "--timeout", str(timeout)]
            command += ["--min-priority", str(self._int_value(self.min_priority_var, "Minimum priority", 0, 100))]
            if self.methods_var.get().strip():
                command += ["--methods", self.methods_var.get().strip()]

        elif self.mode == "crawl":
            command += [
                "-u",
                target,
                "--timeout",
                str(timeout),
                "--max-pages",
                str(self._int_value(self.max_pages_var, "Maximum pages", 1, 100000)),
                "--max-depth",
                str(self._int_value(self.max_depth_var, "Maximum depth", 0, 100)),
                "--delay",
                str(self._float_value(self.delay_var, "Request delay", 0.0, 60.0)),
            ]
            if self.no_assets_var.get():
                command.append("--no-assets")
            if self.params_only_var.get():
                command.append("--params-only")

        command += ["-o", str(result_path), "--format", "json"]
        return command, result_path

    @staticmethod
    def _int_value(variable: tk.StringVar, label: str, minimum: int, maximum: int) -> int:
        try:
            value = int(variable.get().strip())
        except ValueError as exc:
            raise ValueError(f"{label} must be a whole number.") from exc
        if not minimum <= value <= maximum:
            raise ValueError(f"{label} must be between {minimum} and {maximum}.")
        return value

    @staticmethod
    def _float_value(variable: tk.StringVar, label: str, minimum: float, maximum: float) -> float:
        try:
            value = float(variable.get().strip())
        except ValueError as exc:
            raise ValueError(f"{label} must be a number.") from exc
        if not minimum <= value <= maximum:
            raise ValueError(f"{label} must be between {minimum} and {maximum}.")
        return value

    def _run_process(self, command: list[str]) -> None:
        env = os.environ.copy()
        env.update({"PYTHONUTF8": "1", "PYTHONUNBUFFERED": "1", "NO_COLOR": "1"})
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            process = subprocess.Popen(
                command,
                cwd=str(APP_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                env=env,
                creationflags=creationflags,
            )
            with self.process_lock:
                self.process = process
            if self.cancel_requested:
                process.terminate()
            assert process.stdout is not None
            for line in process.stdout:
                self.events.put(("line", ANSI_RE.sub("", line)))
            return_code = process.wait()
            self.events.put(("done", return_code))
        except Exception as exc:
            self.events.put(("error", str(exc)))
        finally:
            with self.process_lock:
                self.process = None

    def _cancel_scan(self) -> None:
        if not self.scan_active:
            return
        self.cancel_requested = True
        with self.process_lock:
            process = self.process
        self.cancel_button.configure(state="disabled")
        self._set_status("Cancelling scan", "warning")
        self._append_log("\nCancellation requested…\n", "warning")
        if process is not None:
            try:
                process.terminate()
            except Exception:
                pass

    def _drain_events(self) -> None:
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "line":
                    self._append_log(event[1], self._log_tag(event[1]))
                elif kind == "done":
                    self._finish_scan(event[1])
                elif kind == "error":
                    self._append_log(f"\nUnable to start scan: {event[1]}\n", "error")
                    self._finish_scan(1)
                elif kind == "setup_line":
                    self._append_log(event[1], self._log_tag(event[1]))
                elif kind == "setup_done":
                    self._finish_subfinder_setup(event[1])
                elif kind == "setup_error":
                    self._append_log(f"\nSetup failed: {event[1]}\n", "error")
                    self._finish_subfinder_setup(1)
        except queue.Empty:
            pass
        self.after(80, self._drain_events)

    def _finish_scan(self, return_code: int) -> None:
        duration = max(0.0, time.monotonic() - self.started_at)
        self.scan_active = False
        self.progress.stop()
        self.progress.grid_remove()
        self.run_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self._set_navigation_enabled(True)
        self.metric_values["duration"].configure(text=f"{duration:.1f}s")
        self.elapsed_label.configure(text=f"Completed in {duration:.1f}s")

        if self.cancel_requested:
            self._set_status("Scan cancelled", "warning")
            return
        if return_code != 0:
            self._set_status("Scan failed", "error")
            self._append_log(f"\nProcess exited with code {return_code}.\n", "error")
            return

        self._load_results()
        self._set_status("Scan completed", "success")
        self._append_log("\nScan completed successfully.\n", "success")
        if self.result_rows:
            self.notebook.select(self.results_tab)

    def _update_elapsed(self) -> None:
        if self.run_button.instate(["disabled"]):
            elapsed = max(0.0, time.monotonic() - self.started_at)
            self.elapsed_label.configure(text=f"Elapsed {elapsed:.1f}s")
            self.after(500, self._update_elapsed)

    # ------------------------------------------------------------------
    # Results and utility actions
    # ------------------------------------------------------------------

    def _load_results(self) -> None:
        self.result_rows = []
        if self.result_path and self.result_path.exists():
            try:
                data = json.loads(self.result_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data:
                        self.result_rows.append(item if isinstance(item, dict) else {"subdomain": str(item)})
            except Exception as exc:
                self._append_log(f"Could not read structured results: {exc}\n", "warning")

        if self.mode == "subs":
            secondary = sum(1 for item in self.result_rows if int(item.get("status", 0) or 0) > 0)
        elif self.mode == "crawl":
            secondary = sum(1 for item in self.result_rows if item.get("category") == "error")
        else:
            secondary = sum(1 for item in self.result_rows if int(item.get("priority", 0) or 0) >= 80)
        self.metric_values["results"].configure(text=str(len(self.result_rows)))
        self.metric_values["priority"].configure(text=str(secondary) if secondary else "—")
        self._render_results()

    def _render_results(self) -> None:
        if not hasattr(self, "results_tree"):
            return
        tree = self.results_tree
        tree.delete(*tree.get_children())

        if self.mode == "subs":
            columns = ("status", "scheme", "subdomain", "title")
            widths = (75, 75, 310, 230)
        elif self.mode in ("endpoints", "full"):
            columns = ("priority", "method", "url", "source", "description")
            widths = (75, 75, 390, 100, 230)
        else:
            columns = ("status", "method", "url", "category", "content_type")
            widths = (75, 75, 410, 100, 150)

        tree.configure(columns=columns)
        for column, width in zip(columns, widths):
            tree.heading(column, text=column.replace("_", " ").upper())
            tree.column(column, width=width, minwidth=60, stretch=column in ("url", "subdomain", "description"))

        query = self.search_var.get().strip().lower()
        visible = 0
        for row in self.result_rows:
            if query and query not in json.dumps(row, ensure_ascii=False).lower():
                continue
            values = tuple(str(row.get(column, "")) for column in columns)
            priority = int(row.get("priority", 0) or 0)
            status = int(row.get("status", 0) or 0)
            tag = "high" if priority >= 80 or status >= 500 else "medium" if priority >= 60 or status >= 400 else "good" if status and status < 400 else ""
            tree.insert("", "end", values=values, tags=(tag,) if tag else ())
            visible += 1

        if visible:
            self.empty_results.place_forget()
        else:
            message = "No matching results." if self.result_rows else "Results will appear here after a scan."
            self.empty_results.configure(text=message)
            self.empty_results.place(relx=0.5, rely=0.45, anchor="center")

    def _reset_results(self) -> None:
        self.result_rows = []
        self.search_var.set("")
        for value in self.metric_values.values():
            value.configure(text="—")
        self._render_results()

    def _choose_output(self) -> None:
        chosen = filedialog.asksaveasfilename(
            parent=self,
            title="Save scan results",
            defaultextension=".json",
            filetypes=(("JSON results", "*.json"), ("All files", "*.*")),
        )
        if chosen:
            self.output_var.set(chosen)

    def _open_results_folder(self) -> None:
        folder = self.result_path.parent if self.result_path else RESULTS_DIR
        folder.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(str(folder))  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(folder)])
            else:
                subprocess.Popen(["xdg-open", str(folder)])
        except Exception as exc:
            messagebox.showerror("Open results folder", str(exc), parent=self)

    def _refresh_engine_status(self) -> None:
        path = _locate_subfinder()
        if path:
            self.engine_status_label.configure(text="Subfinder ready", fg=COLORS["accent"])
            self.engine_button.configure(text="Extended coverage installed", state="disabled")
        else:
            self.engine_status_label.configure(text="Basic providers only", fg=COLORS["amber"])
            self.engine_button.configure(text="Install extended engine", state="normal")

    def _install_subfinder(self) -> None:
        if self.scan_active or self.setup_active:
            return
        script = APP_DIR / "install-subfinder.ps1"
        if not script.exists():
            messagebox.showerror("Install Subfinder", "The installer script is missing.", parent=self)
            return
        approved = messagebox.askyesno(
            "Install extended discovery engine",
            "Download the latest official ProjectDiscovery Subfinder release?\n\n"
            "The installer verifies ProjectDiscovery's published SHA-256 checksum before installation.",
            parent=self,
        )
        if not approved:
            return

        self.setup_active = True
        self.run_button.configure(state="disabled")
        self.engine_button.configure(state="disabled", text="Installing…")
        self.notebook.select(self.activity_tab)
        self._clear_log()
        self._append_log("Installing the extended discovery engine\n", "heading")
        self._append_log("Source: official ProjectDiscovery GitHub release\n\n", "muted")
        self._set_status("Installing Subfinder", "running")
        threading.Thread(target=self._run_subfinder_setup, args=(script,), daemon=True).start()

    def _run_subfinder_setup(self, script: Path) -> None:
        creationflags = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0
        try:
            process = subprocess.Popen(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy",
                    "Bypass",
                    "-File",
                    str(script),
                ],
                cwd=str(APP_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creationflags,
            )
            self.setup_process = process
            assert process.stdout is not None
            for line in process.stdout:
                self.events.put(("setup_line", line))
            self.events.put(("setup_done", process.wait()))
        except Exception as exc:
            self.events.put(("setup_error", str(exc)))
        finally:
            self.setup_process = None

    def _finish_subfinder_setup(self, return_code: int) -> None:
        self.setup_active = False
        self._refresh_engine_status()
        self.run_button.configure(state="normal")
        if return_code == 0 and _locate_subfinder():
            self._append_log("\nExtended discovery is ready.\n", "success")
            self._set_status("Subfinder installed", "success")
        else:
            self._append_log(f"\nInstaller exited with code {return_code}.\n", "error")
            self._set_status("Subfinder setup failed", "error")

    def _copy_selected(self) -> None:
        selected = self.results_tree.selection()
        if not selected:
            return
        values = self.results_tree.item(selected[0], "values")
        text = "\t".join(str(value) for value in values)
        self.clipboard_clear()
        self.clipboard_append(text)
        self._set_status("Selected result copied", "success")

    def _clear_log(self) -> None:
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")

    def _append_log(self, text: str, tag: str = "muted") -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text, tag)
        self.log.see("end")
        self.log.configure(state="disabled")

    @staticmethod
    def _log_tag(line: str) -> str:
        lowered = line.lower()
        if "fatal" in lowered or "error" in lowered or "✘" in line:
            return "error"
        if "warning" in lowered or "skipped" in lowered or "⚠" in line:
            return "warning"
        if "saved" in lowered or "found in" in lowered or "✔" in line:
            return "success"
        if "→" in line or "enumeration" in lowered or "discovery" in lowered or "crawler" in lowered:
            return "heading"
        return "muted"

    def _set_status(self, text: str, state: str) -> None:
        color = {
            "idle": COLORS["quiet"],
            "running": COLORS["blue"],
            "success": COLORS["accent"],
            "warning": COLORS["amber"],
            "error": COLORS["red"],
        }.get(state, COLORS["quiet"])
        self.status_dot.configure(fg=color)
        self.status_label.configure(text=text, fg=color if state != "idle" else COLORS["muted"])

    def _set_navigation_enabled(self, enabled: bool) -> None:
        state = "normal" if enabled else "disabled"
        for button in self.nav_buttons.values():
            button.configure(state=state)

    def _report_callback_exception(self, exc_type, exc_value, exc_traceback) -> None:
        messagebox.showerror("Unexpected application error", str(exc_value), parent=self)

    def _on_close(self) -> None:
        if self.scan_active or self.setup_active:
            close = messagebox.askyesno(
                "Close Scan",
                "A background operation is still running. Cancel it and close the application?",
                parent=self,
            )
            if not close:
                return
            if self.scan_active:
                self._cancel_scan()
            if self.setup_process is not None:
                try:
                    self.setup_process.terminate()
                except Exception:
                    pass
        self.destroy()


def smoke_test() -> int:
    """Construct every view without starting a network scan."""
    app = ScanDesktop()
    app.withdraw()
    app.update_idletasks()
    for mode in MODES:
        app._select_mode(mode)
        app.update_idletasks()
        if mode == "subs" and app.live_only_var.get():
            raise AssertionError("Subdomain discovery must not filter to live hosts by default")
        if mode == "full" and not app.live_only_var.get():
            raise AssertionError("Full recon should use reachable hosts by default")
    app.destroy()
    print("Desktop UI smoke test passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--smoke-test", action="store_true")
    args, _unknown = parser.parse_known_args()
    enable_windows_dpi_awareness()
    if args.smoke_test:
        return smoke_test()
    app = ScanDesktop()
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
