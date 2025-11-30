# gui.py    (Tkinter GUI: select path, run scan, show results in Treeview, export buttons)
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
from scanner import scan_path
from utils import export_json, export_html
import os
import time
import json

class App:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Rhombix Debugger — Python Static Scanner")
        self.root.geometry("900x600")
        self._build_ui()

    def _build_ui(self):
        frm = ttk.Frame(self.root, padding=10)
        frm.pack(fill=tk.BOTH, expand=True)

        # Path selection
        pathfrm = ttk.Frame(frm)
        pathfrm.pack(fill=tk.X, pady=5)
        ttk.Label(pathfrm, text="Path to scan (file or folder):").pack(side=tk.LEFT)
        self.path_var = tk.StringVar()
        ttk.Entry(pathfrm, textvariable=self.path_var, width=70).pack(side=tk.LEFT, padx=5)
        ttk.Button(pathfrm, text="Browse", command=self.browse).pack(side=tk.LEFT, padx=5)

        # Controls
        ctrlfrm = ttk.Frame(frm)
        ctrlfrm.pack(fill=tk.X, pady=5)
        self.scan_btn = ttk.Button(ctrlfrm, text="Run Scan", command=self.run_scan_thread)
        self.scan_btn.pack(side=tk.LEFT)
        self.export_json_btn = ttk.Button(ctrlfrm, text="Export JSON", command=self.export_json, state=tk.DISABLED)
        self.export_json_btn.pack(side=tk.LEFT, padx=5)
        self.export_html_btn = ttk.Button(ctrlfrm, text="Export HTML", command=self.export_html, state=tk.DISABLED)
        self.export_html_btn.pack(side=tk.LEFT, padx=5)

        # Progress label
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(frm, textvariable=self.status_var).pack(fill=tk.X, pady=3)

        # Results treeview
        cols = ("file", "line", "type", "severity", "message")
        self.tree = ttk.Treeview(frm, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=150)
        self.tree.column("message", width=350)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=5)
        self.tree.bind("<Double-1>", self.on_item_double)

        # Detail box
        self.detail = tk.Text(frm, height=8)
        self.detail.pack(fill=tk.X)

        # internal
        self.issues = []
        self.scanned_path = None

    def browse(self):
        path = filedialog.askdirectory() or filedialog.askopenfilename()
        if path:
            self.path_var.set(path)

    def run_scan_thread(self):
        path = self.path_var.get().strip()
        if not path:
            messagebox.showwarning("No path", "Select file or folder to scan.")
            return
        self.scan_btn.config(state=tk.DISABLED)
        self.status_var.set("Scanning...")
        t = threading.Thread(target=self._scan, args=(path,))
        t.start()

    def _scan(self, path):
        start = time.time()
        try:
            issues = scan_path(path, recursive=True, extensions=(".py",))
            self.issues = issues
            self.scanned_path = path
            self._populate_tree()
            self.status_var.set(f"Scan complete in {time.time()-start:.2f}s — {len(issues)} issues found")
            if issues:
                self.export_json_btn.config(state=tk.NORMAL)
                self.export_html_btn.config(state=tk.NORMAL)
        except Exception as e:
            messagebox.showerror("Scan error", str(e))
            self.status_var.set("Error during scan.")
        finally:
            self.scan_btn.config(state=tk.NORMAL)

    def _populate_tree(self):
        # clear
        for i in self.tree.get_children():
            self.tree.delete(i)
        for idx, issue in enumerate(self.issues):
            item = self.tree.insert("", "end", iid=str(idx),
                                    values=(issue.filepath, issue.lineno, issue.issue_type, issue.severity, issue.message))
            # attach full dict as tag
            self.tree.set(item, "message", issue.message)

    def on_item_double(self, event):
        sel = self.tree.selection()
        if not sel: return
        idx = int(sel[0])
        issue = self.issues[idx]
        # show detailed info and suggestion
        self.detail.delete("1.0", tk.END)
        txt = f"File: {issue.filepath}\nLine: {issue.lineno}\nType: {issue.issue_type}\nSeverity: {issue.severity}\n\nMessage:\n{issue.message}\n\nSuggestion:\n{issue.suggestion}\n"
        self.detail.insert(tk.END, txt)

    def export_json(self):
        out = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files","*.json")], initialfile="rhombix_report.json")
        if not out:
            return
        import utils
        utils.export_json(self.issues, out)
        messagebox.showinfo("Exported", f"JSON exported to {out}")

    def export_html(self):
        out = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML files","*.html")], initialfile="rhombix_report.html")
        if not out:
            return
        import utils
        utils.export_html(self.issues, self.scanned_path, out)
        messagebox.showinfo("Exported", f"HTML report exported to {out}")

    def run(self):
        self.root.mainloop()
