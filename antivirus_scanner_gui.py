#!/usr/bin/env python3
"""Tkinter frontend for antivirus_scanner."""

from __future__ import annotations

import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from antivirus_scanner import scan_target, summarize_results


class AntivirusScannerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Antivirus File Scanner")
        self.root.geometry("860x540")

        self.target_var = tk.StringVar()
        self.recursive_var = tk.BooleanVar(value=True)
        self._build_ui()

    def _build_ui(self) -> None:
        frame = ttk.Frame(self.root, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        top = ttk.Frame(frame)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Target file/folder:").pack(anchor=tk.W)

        target_row = ttk.Frame(top)
        target_row.pack(fill=tk.X, pady=(4, 8))

        ttk.Entry(target_row, textvariable=self.target_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(target_row, text="File...", command=self.choose_file).pack(side=tk.LEFT, padx=(8, 4))
        ttk.Button(target_row, text="Folder...", command=self.choose_folder).pack(side=tk.LEFT)

        ttk.Checkbutton(
            top,
            text="Recursive directory scan",
            variable=self.recursive_var,
        ).pack(anchor=tk.W, pady=(0, 8))

        ttk.Button(top, text="Scan", command=self.start_scan).pack(anchor=tk.W)

        ttk.Separator(frame).pack(fill=tk.X, pady=12)

        self.output = tk.Text(frame, wrap=tk.NONE)
        self.output.pack(fill=tk.BOTH, expand=True)
        self.output.configure(state=tk.DISABLED)

    def choose_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file to scan")
        if path:
            self.target_var.set(path)

    def choose_folder(self) -> None:
        path = filedialog.askdirectory(title="Select folder to scan")
        if path:
            self.target_var.set(path)

    def start_scan(self) -> None:
        raw_target = self.target_var.get().strip()
        if not raw_target:
            messagebox.showwarning("Missing target", "Please choose a file or folder to scan.")
            return

        target = Path(raw_target).expanduser().resolve()
        if not target.exists():
            messagebox.showerror("Invalid target", f"Target does not exist:\n{target}")
            return

        self._set_output("Scanning...\n")
        worker = threading.Thread(
            target=self._run_scan,
            args=(target, self.recursive_var.get()),
            daemon=True,
        )
        worker.start()

    def _run_scan(self, target: Path, recursive: bool) -> None:
        results = scan_target(target, recursive=recursive)

        if not results:
            self._append_output(f"No files found to scan in: {target}\n")
            return

        for result in results:
            if result.status == "OK":
                line = f"[OK] {result.target}\n"
            elif result.status == "FOUND":
                suffix = f" ({result.details})" if result.details else ""
                line = f"[INFECTED] {result.target}{suffix}\n"
            else:
                line = f"[ERROR] {result.target}: {result.details}\n"
            self._append_output(line)

        infected, errors = summarize_results(results)
        summary = (
            "\nSummary\n"
            f"  Files scanned: {len(results)}\n"
            f"  Infected:      {infected}\n"
            f"  Errors:        {errors}\n"
        )
        self._append_output(summary)

    def _set_output(self, text: str) -> None:
        self.output.configure(state=tk.NORMAL)
        self.output.delete("1.0", tk.END)
        self.output.insert(tk.END, text)
        self.output.configure(state=tk.DISABLED)

    def _append_output(self, text: str) -> None:
        def _append() -> None:
            self.output.configure(state=tk.NORMAL)
            self.output.insert(tk.END, text)
            self.output.see(tk.END)
            self.output.configure(state=tk.DISABLED)

        self.root.after(0, _append)


def main() -> None:
    root = tk.Tk()
    app = AntivirusScannerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
