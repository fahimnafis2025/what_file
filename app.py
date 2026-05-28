import os
import threading
import customtkinter as ctk
from tkinter import filedialog, messagebox
import tkinter as tk
import time

# Import the actual functional backend engine
from analyzer import FileAnalyzerEngine

# ─── Palette ─────────────────────────────────────────────────────────────────
BG_ROOT       = "#080c08"   # near-black root
BG_PANEL      = "#0b100b"   # sidebar
BG_CARD       = "#0f160f"   # result cards
BG_CARD_ALT   = "#161f16"   # alternating data rows
BORDER        = "#1e3a1e"   # card borders
BORDER_BRIGHT = "#3a6b3a"   # hover borders

GREEN         = "#00ff41"   # phosphor — primary accent / logo
GREEN_DIM     = "#5de874"   # body text
GREEN_LABEL   = "#7fff97"   # row keys / section tags
GREEN_MUTED   = "#4aaa5a"   # explanations / meta
GREEN_DARK    = "#0a2e14"   # button fill

AMBER         = "#ffcf6b"   # warnings
RED           = "#ff6b6b"   # danger
CYAN          = "#33eeff"   # network / info
WHITE         = "#eaf5ea"   # primary body text

FONT_MONO     = ("Courier", 12)
FONT_MONO_SM  = ("Courier", 11)
FONT_MONO_LG  = ("Courier", 15, "bold")
FONT_MONO_XL  = ("Courier", 21, "bold")
FONT_MONO_H   = ("Courier", 13, "bold")

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("dark-blue")


# ─── Blinking cursor ──────────────────────────────────────────────────────────
class BlinkingCursor(ctk.CTkLabel):
    def __init__(self, master, **kwargs):
        super().__init__(master, text="▮", text_color=GREEN, font=FONT_MONO_LG, **kwargs)
        self._on = True
        self._task = None
        self._blink()

    def _blink(self):
        self._on = not self._on
        self.configure(text="▮" if self._on else " ")
        self._task = self.after(530, self._blink)

    def destroy(self):
        if self._task:
            self.after_cancel(self._task)
        super().destroy()


def _divider(parent, color=None):
    bg_color = color or BORDER
    tk.Frame(parent, height=1, bg=bg_color).pack(fill="x", pady=6)


# ─── Main App ─────────────────────────────────────────────────────────────────
class MalwareWorkbenchApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("STATIC WHAT_FILE WORKBENCH  //  OFFLINE MODE")
        self.geometry("1100x740")
        self.minsize(900, 600)
        self.configure(fg_color=BG_ROOT)

        # Connect the functional engine
        self.engine = FileAnalyzerEngine()
        self.target_file = None
        self._last_results = {}

        self._build_ui()
        threading.Thread(target=self._startup_check, daemon=True).start()

    # ─── Build UI ────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=268, corner_radius=0,
                                    fg_color=BG_PANEL, border_width=0)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Frame(self, width=1, bg=BORDER).pack(side="left", fill="y")

        # Sidebar — header
        hdr = ctk.CTkFrame(self.sidebar, fg_color=BG_ROOT, corner_radius=0)
        hdr.pack(fill="x")
        tk.Frame(hdr, height=2, bg=GREEN).pack(fill="x")

        ctk.CTkLabel(hdr, text="[ WHAT_FILE ]", font=FONT_MONO_XL,
                     text_color=GREEN, anchor="w").pack(padx=18, pady=(14, 0), anchor="w")
        ctk.CTkLabel(hdr, text="STATIC MALWARE WORKBENCH", font=FONT_MONO_SM,
                     text_color=GREEN_MUTED, anchor="w").pack(padx=18, pady=(2, 2), anchor="w")
        ctk.CTkLabel(hdr, text="OFFLINE ● AIRGAPPED ● READ-ONLY", font=FONT_MONO_SM,
                     text_color=GREEN_MUTED, anchor="w").pack(padx=18, pady=(0, 12), anchor="w")
        tk.Frame(hdr, height=1, bg=BORDER).pack(fill="x")

        # Sidebar — controls
        ctrl = ctk.CTkFrame(self.sidebar, fg_color="transparent", corner_radius=0)
        ctrl.pack(fill="x", padx=18, pady=18)

        ctk.CTkLabel(ctrl, text="// TARGET FILE", font=FONT_MONO_SM,
                     text_color=GREEN_LABEL, anchor="w").pack(anchor="w", pady=(0, 6))

        self.select_btn = self._btn(ctrl, "  [ SELECT FILE ]", self._select_file)
        self.select_btn.pack(fill="x", pady=3)

        self.file_label = ctk.CTkLabel(ctrl, text="no file loaded",
                                       text_color=GREEN_MUTED, font=FONT_MONO_SM,
                                       anchor="w", wraplength=220, justify="left")
        self.file_label.pack(anchor="w", pady=(4, 14))

        _divider(ctrl)

        ctk.CTkLabel(ctrl, text="// ANALYSIS", font=FONT_MONO_SM,
                     text_color=GREEN_LABEL, anchor="w").pack(anchor="w", pady=(6, 6))

        self.analyze_btn = self._btn(ctrl, "  [ RUN ANALYSIS ]", self._start_analysis,
                                     state="disabled", accent=True)
        self.analyze_btn.pack(fill="x", pady=3)

        _divider(ctrl)

        # Module list
        ctk.CTkLabel(ctrl, text="// ACTIVE MODULES", font=FONT_MONO_SM,
                     text_color=GREEN_LABEL, anchor="w").pack(anchor="w", pady=(6, 6))

        self._modules = [
            "FILE IDENTIFICATION", "CRYPTOGRAPHIC INTEL", 
            "LOCAL ANTIVIRUS SCAN", "YARA RULE MATCHES", 
            "NETWORK INDICATORS"
        ]
        for name in self._modules:
            row = ctk.CTkFrame(ctrl, fg_color="transparent", corner_radius=0)
            row.pack(fill="x", pady=1)
            ctk.CTkLabel(row, text="▪ ", text_color=GREEN,
                         font=FONT_MONO_SM, width=18).pack(side="left")
            ctk.CTkLabel(row, text=name, text_color=GREEN_DIM,
                         font=FONT_MONO_SM, anchor="w").pack(side="left")

        # Sidebar — status bar
        sb = ctk.CTkFrame(self.sidebar, fg_color=BG_ROOT, corner_radius=0, height=48)
        sb.pack(side="bottom", fill="x")
        sb.pack_propagate(False)
        tk.Frame(sb, height=1, bg=BORDER).pack(fill="x")

        row = ctk.CTkFrame(sb, fg_color="transparent", corner_radius=0)
        row.pack(fill="x", padx=14, pady=10)
        self._cursor = BlinkingCursor(row)
        self._cursor.pack(side="left")
        self.status_label = ctk.CTkLabel(row, text=" SYSTEM READY",
                                         text_color=GREEN, font=FONT_MONO_SM, anchor="w")
        self.status_label.pack(side="left")

        # Main panel
        self.main = ctk.CTkFrame(self, corner_radius=0, fg_color=BG_ROOT, border_width=0)
        self.main.pack(side="right", fill="both", expand=True)

        # Toolbar
        tb = ctk.CTkFrame(self.main, fg_color=BG_PANEL, corner_radius=0, height=36)
        tb.pack(fill="x")
        tb.pack_propagate(False)
        ctk.CTkLabel(tb, text="  OUTPUT  //  ANALYSIS RESULTS",
                     font=FONT_MONO_SM, text_color=GREEN_LABEL,
                     anchor="w").pack(side="left", padx=14, pady=8)
        self._ts_label = ctk.CTkLabel(tb, text="", font=FONT_MONO_SM, text_color=GREEN_MUTED)
        self._ts_label.pack(side="right", padx=14)
        tk.Frame(self.main, height=1, bg=BORDER).pack(fill="x")

        # Scrollable results
        self.results_frame = ctk.CTkScrollableFrame(
            self.main, corner_radius=0, fg_color=BG_ROOT,
            scrollbar_button_color=BORDER, scrollbar_button_hover_color=BORDER_BRIGHT,
        )
        self.results_frame.pack(fill="both", expand=True)

        self._show_splash()

    # ─── Widget factory ───────────────────────────────────────────────────────
    def _btn(self, parent, text, cmd, state="normal", accent=False):
        return ctk.CTkButton(
            parent, text=text, font=FONT_MONO, command=cmd, state=state,
            fg_color=GREEN_DARK if accent else BG_ROOT,
            hover_color="#0d3d1a" if accent else "#111811",
            border_color=GREEN if accent else BORDER_BRIGHT,
            border_width=1,
            text_color=GREEN,
            text_color_disabled=GREEN_MUTED,
            corner_radius=3, height=34,
        )

    # ─── Splash ───────────────────────────────────────────────────────────────
    def _show_splash(self):
        for w in self.results_frame.winfo_children():
            w.destroy()

        f = ctk.CTkFrame(self.results_frame, fg_color="transparent", corner_radius=0)
        f.pack(expand=True, fill="both", pady=60)

        ctk.CTkLabel(f, font=("Courier", 9, "bold"), text_color=GREEN_MUTED, justify="left",
                     text=(
                         " ██╗    ██╗██╗  ██╗ █████╗ ████████╗    ███████╗██████╗ ██╗     ███████╗\n"
                         " ██║    ██║██║  ██║██╔══██╗╚══██╔══╝    ██╔════╝╚═██╔═╝ ██║     ██╔════╝\n"
                         " ██║ █╗ ██║███████║███████║   ██║       █████╗    ██║   ██║     █████╗  \n"
                         " ██║███╗██║██╔══██║██╔══██║   ██║       ██╔══╝    ██║   ██║     ██╔══╝  \n"
                         " ╚███╔███╔╝██║  ██║██║  ██║   ██║       ██║     ██████╗ ███████╗███████╗\n"
                         "  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝       ╚═╝     ╚═════╝ ╚══════╝╚══════╝"
                     )).pack()

        ctk.CTkLabel(f, text="\nOFFLINE STATIC MALWARE WHAT_FILE WORKBENCH  v2.1.0",
                     font=FONT_MONO_LG, text_color=GREEN).pack()
        ctk.CTkLabel(f, font=FONT_MONO_SM, text_color=GREEN_MUTED, justify="center",
                     text="\nAWAITING TARGET FILE  ·  ALL ANALYSIS RUNS LOCALLY\n"
                          "NO NETWORK CALLS  ·  NO TELEMETRY  ·  READ-ONLY MODE").pack()

        tk.Frame(f, height=1, bg=BORDER).pack(fill="x", padx=80, pady=16)

        ctk.CTkLabel(f, font=FONT_MONO_SM, text_color=GREEN_MUTED, justify="center",
                     text="SUPPORTED:  EXE  DLL  PDF  DOCX  ZIP  ELF  MACH-O  APK  JAR\n"
                          "ENGINES:    file  exiftool  strings  yara  clamscan").pack()

    # ─── Startup check ────────────────────────────────────────────────────────
    def _startup_check(self):
        self._set_status("CHECKING DEPS...", AMBER)
        missing = self.engine.get_missing_tools()
        if missing:
            self._set_status("MISSING TOOLS", RED)
            if messagebox.askyesno("Missing Dependencies",
                                   f"The following tools are missing:\n{', '.join(missing)}\n\nInstall them now? (Requires authorization)"):
                self._set_status("INSTALLING...", AMBER)
                success = self.engine.install_tools(missing)
                self._set_status("SYSTEM READY" if success else "INSTALL FAILED",
                                 GREEN if success else RED)
            else:
                self._set_status("LIMITED MODE", AMBER)
        else:
            self._set_status("SYSTEM READY", GREEN)

            # Auto setup YARA rules folder quietly on launch if missing
            if not os.path.exists(self.engine.yara_rules_dir) or not os.listdir(self.engine.yara_rules_dir):
                # FIX: Prompt the user in the GUI instead of doing a silent network call
                if messagebox.askyesno("Missing YARA Rules", 
                                       "The local YARA community rules repository is empty.\n\n"
                                       "Would you like to download the standard ruleset from GitHub now? "
                                       "(This is the ONLY time the app will require an internet connection)"):
                    self._set_status("DOWNLOADING RULES...", AMBER)
                    
                    def _fetch_rules():
                        success = self.engine.setup_yara_rules()
                        # Use self.after to safely update Tkinter from a background thread
                        self.after(0, lambda: self._set_status(
                            "SYSTEM READY" if success else "RULE DOWNLOAD FAILED",
                            GREEN if success else RED
                        ))
                        if success:
                            self.after(0, lambda: messagebox.showinfo("Rules Downloaded", "YARA rules successfully installed for offline use!"))
                            
                    threading.Thread(target=_fetch_rules, daemon=True).start()

    def _set_status(self, msg, color=GREEN):
        self.status_label.configure(text=f" {msg}", text_color=color)

    # ─── File selection ───────────────────────────────────────────────────────
    def _select_file(self):
        path = filedialog.askopenfilename(title="Select suspicious file")
        if path:
            self.target_file = path
            size = os.path.getsize(path)
            size_str = f"{size:,} B" if size < 1_048_576 else f"{size/1_048_576:.2f} MB"
            self.file_label.configure(
                text=f"{os.path.basename(path)}\n{size_str}",
                text_color=GREEN_DIM,
            )
            self.analyze_btn.configure(state="normal")
            self._set_status("TARGET LOADED", GREEN)

    # ─── Analysis ─────────────────────────────────────────────────────────────
    def _start_analysis(self):
        self.analyze_btn.configure(state="disabled")
        self.select_btn.configure(state="disabled")
        self._set_status("ANALYZING...", AMBER)
        self._ts_label.configure(text=f"STARTED  {time.strftime('%H:%M:%S')}")

        for w in self.results_frame.winfo_children():
            w.destroy()

        scan_lbl = ctk.CTkLabel(self.results_frame, text="",
                                font=FONT_MONO_SM, text_color=GREEN_DIM, anchor="w")
        scan_lbl.pack(fill="x", padx=28, pady=24)
        self._animate_scan(scan_lbl, 0)

        threading.Thread(target=self._run_engine, daemon=True).start()

    def _animate_scan(self, lbl, step):
        steps = [
            "  [ ░░░░░░░░░░░░░░░░░░░░ ]  INITIALIZING ENGINES...",
            "  [ ████░░░░░░░░░░░░░░░░ ]  PARSING FILE SIGNATURE...",
            "  [ ████████░░░░░░░░░░░░ ]  RUNNING CLAMAV SCAN...",
            "  [ ████████████░░░░░░░░ ]  PROCESSING YARA RULES...",
            "  [ ████████████████░░░░ ]  EXTRACTING PLAINTEXT STRINGS...",
            "  [ ████████████████████ ]  COMPILING GENERATED REPORT...",
        ]
        if step < len(steps):
            try:
                lbl.configure(text=steps[step])
                self.after(400, self._animate_scan, lbl, step + 1)
            except Exception:
                pass

    def _run_engine(self):
        # Fire the actual functional backend process
        results = self.engine.analyze(self.target_file)
        self.after(0, self._render_results, results)

    # ─── Render results ───────────────────────────────────────────────────────
    def _render_results(self, results: dict):
        self._last_results = results
        self.analyze_btn.configure(state="normal")
        self.select_btn.configure(state="normal")
        self._set_status("ANALYSIS COMPLETE", GREEN)
        self._ts_label.configure(text=f"COMPLETE  {time.strftime('%H:%M:%S')}")

        for w in self.results_frame.winfo_children():
            w.destroy()

        if "Error" in results:
            self._render_error(results["Error"])
            return

        # Report header
        hdr = ctk.CTkFrame(self.results_frame, fg_color="transparent", corner_radius=0)
        hdr.pack(fill="x", padx=28, pady=(18, 4))

        ctk.CTkLabel(hdr, text=f"TARGET  //  {os.path.basename(self.target_file)}",
                     font=FONT_MONO_LG, text_color=GREEN, anchor="w").pack(anchor="w")
        ctk.CTkLabel(hdr,
                     text=f"ANALYZED: {time.strftime('%Y-%m-%d %H:%M:%S')}  ·  "
                          f"MODULES: {len(self._modules)}  ·  FINDINGS: {len(results)}",
                     font=FONT_MONO_SM, text_color=GREEN_MUTED, anchor="w").pack(anchor="w")

        tk.Frame(self.results_frame, height=1, bg=BORDER).pack(fill="x", padx=28, pady=8)

        # Dynamic card creation
        for idx, (category, content) in enumerate(results.items()):
            self._render_card(category, content, idx)

        self._render_export_prompt()

    def _render_card(self, category: str, content, idx: int):
        accent = [GREEN, CYAN, AMBER, RED, GREEN_DIM, AMBER][idx % 6]

        outer = ctk.CTkFrame(self.results_frame, fg_color=BG_CARD,
                             corner_radius=4, border_width=1, border_color=BORDER)
        outer.pack(fill="x", padx=28, pady=5)

        tk.Frame(outer, width=4, bg=accent).pack(side="left", fill="y")

        inner = ctk.CTkFrame(outer, fg_color="transparent", corner_radius=0)
        inner.pack(side="left", fill="both", expand=True, padx=14, pady=12)

        # Title row
        cat_row = ctk.CTkFrame(inner, fg_color="transparent", corner_radius=0)
        cat_row.pack(fill="x")
        ctk.CTkLabel(cat_row, text=f"[{str(idx+1).zfill(2)}]",
                     font=FONT_MONO_SM, text_color=GREEN_MUTED).pack(side="left", padx=(0, 8))
        ctk.CTkLabel(cat_row, text=category.upper(),
                     font=FONT_MONO_H, text_color=accent).pack(side="left")

        # Simple string result handling (like File Type Identification)
        if isinstance(content, str):
            ctk.CTkLabel(inner, text=f"  →  {content}", font=FONT_MONO,
                         text_color=WHITE, anchor="w", wraplength=680,
                         justify="left").pack(anchor="w", pady=(8, 2))
            return

        # Explanation meta handler
        if isinstance(content, dict) and "explanation" in content:
            ctk.CTkLabel(inner, text=f"  {content['explanation']}",
                         font=FONT_MONO_SM, text_color=GREEN_MUTED,
                         anchor="w", wraplength=680, justify="left").pack(anchor="w", pady=(6, 4))

        data = content.get("data") if isinstance(content, dict) else None
        if data is None:
            return

        tk.Frame(inner, height=1, bg=BORDER).pack(fill="x", pady=4)

        # Core Data Layout Engine
        if isinstance(data, dict):
            for key, val in data.items():
                if isinstance(val, list):
                    for subitem in val:
                        self._create_data_row(inner, f"{key} »", subitem)
                else:
                    self._create_data_row(inner, key, val)

        elif isinstance(data, list):
            for item in data:
                self._create_data_row(inner, "Match", item)

    def _create_data_row(self, parent, key: str, val: str):
        """Generates contextual colored text rows inside the UI layout."""
        txt_color = WHITE
        val_str = str(val)
        
        # Color coding logic depending on string content indicators
        if any(w in val_str.upper() for w in ["HIGH", "CRITICAL", "FOUND", "DANGER"]):
            txt_color = RED
        elif any(w in val_str.upper() for w in ["MEDIUM", "WARN", "SUSPICIOUS"]):
            txt_color = AMBER
        elif any(w in val_str.upper() for w in ["HTTP", "HTTPS", "TCP", "UDP"]):
            txt_color = CYAN

        row = ctk.CTkFrame(parent, fg_color=BG_CARD_ALT, corner_radius=2)
        row.pack(fill="x", pady=2)
        
        ctk.CTkLabel(row, text=f"  {key}", font=FONT_MONO_SM,
                     text_color=GREEN_LABEL, width=140, anchor="w").pack(
                         side="left", padx=(6, 0), pady=5)
        ctk.CTkLabel(row, text=val_str, font=FONT_MONO_SM,
                     text_color=txt_color, anchor="w", wraplength=530,
                     justify="left").pack(side="left", padx=10, pady=5)

    # ─── Export prompt ────────────────────────────────────────────────────────
    def _render_export_prompt(self):
        tk.Frame(self.results_frame, height=1, bg=BORDER).pack(fill="x", padx=28, pady=12)

        prompt = ctk.CTkFrame(self.results_frame, fg_color="#0b1a0f",
                              corner_radius=4, border_width=1, border_color=BORDER_BRIGHT)
        prompt.pack(fill="x", padx=28, pady=(0, 28))

        tk.Frame(prompt, width=4, bg=GREEN).pack(side="left", fill="y")

        body = ctk.CTkFrame(prompt, fg_color="transparent", corner_radius=0)
        body.pack(side="left", fill="both", expand=True, padx=16, pady=14)

        ctk.CTkLabel(body, text="REPORT COMPLETE  //  EXPORT OPTIONS",
                     font=FONT_MONO_H, text_color=GREEN, anchor="w").pack(anchor="w")
        ctk.CTkLabel(body,
                     text="Would you like to dump these findings to a plain-text file for archiving or sharing?",
                     font=FONT_MONO_SM, text_color=GREEN_MUTED, anchor="w").pack(anchor="w", pady=(4, 12))

        btn_row = ctk.CTkFrame(body, fg_color="transparent", corner_radius=0)
        btn_row.pack(anchor="w")

        ctk.CTkButton(
            btn_row, text="  [ YES — DUMP TO .TXT ]", font=FONT_MONO,
            command=self._export_to_txt,
            fg_color=GREEN_DARK, hover_color="#0d3d1a",
            border_color=GREEN, border_width=1,
            text_color=GREEN, corner_radius=3, height=34,
        ).pack(side="left", padx=(0, 10))

        ctk.CTkButton(
            btn_row, text="  [ NO — DISCARD ]", font=FONT_MONO,
            command=lambda: prompt.pack_forget(),
            fg_color=BG_ROOT, hover_color="#1a0f0f",
            border_color=BORDER_BRIGHT, border_width=1,
            text_color=GREEN_MUTED, corner_radius=3, height=34,
        ).pack(side="left")

    # ─── Export logic ─────────────────────────────────────────────────────────
    def _export_to_txt(self):
        ts = time.strftime("%Y%m%d_%H%M%S")
        default_name = f"what_file_{os.path.basename(self.target_file or 'report')}_{ts}.txt"

        save_path = filedialog.asksaveasfilename(
            title="Save report as .txt",
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not save_path:
            return

        try:
            with open(save_path, "w", encoding="utf-8") as f:
                f.write(self._format_report_txt())
            messagebox.showinfo("Export Successful", f"Report saved to:\n{save_path}")
            self._set_status("REPORT EXPORTED", GREEN)
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))
            self._set_status("EXPORT FAILED", RED)

    def _format_report_txt(self) -> str:
        sep  = "=" * 72
        thin = "─" * 72
        lines = [
            sep,
            "  WHAT_FILE  //  STATIC MALWARE WORKBENCH — OFFLINE",
            sep,
            f"  TARGET  : {self.target_file}",
            f"  ANALYZED: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  FINDINGS: {len(self._last_results)}",
            sep, "",
        ]

        for idx, (category, content) in enumerate(self._last_results.items(), 1):
            lines.append(f"[{str(idx).zfill(2)}]  {category.upper()}")
            lines.append(thin)

            if isinstance(content, str):
                lines.append(f"  {content}")
            elif isinstance(content, dict):
                if "explanation" in content:
                    lines.append(f"  NOTE: {content['explanation']}")
                    lines.append("")
                data = content.get("data")
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(v, list):
                            for subitem in v:
                                lines.append(f"  {k:<15}: {subitem}")
                        else:
                            lines.append(f"  {k:<15}: {v}")
                elif isinstance(data, list):
                    for item in data:
                        lines.append(f"  »  {item}")

            lines += ["", ""]

        lines += [sep, "  END OF REPORT  ·  ALL FINDINGS ARE HEURISTIC", sep]
        return "\n".join(lines)

    def _render_error(self, msg: str):
        err = ctk.CTkFrame(self.results_frame, fg_color="#1a0000",
                           corner_radius=4, border_width=1, border_color=RED)
        err.pack(fill="x", padx=28, pady=20)
        ctk.CTkLabel(err, text=f"  ERROR  //  {msg}",
                     font=FONT_MONO_H, text_color=RED, anchor="w").pack(padx=14, pady=14)


if __name__ == "__main__":
    app = MalwareWorkbenchApp()
    app.mainloop()
