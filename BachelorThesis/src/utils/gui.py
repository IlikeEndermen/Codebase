import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import os
from io import StringIO
from typing import Dict

from rules.rule_engine import RuleEngine
from rules.rule_executor import RuleExecutor
from utils.file_analyzer import FileAnalyzer


class BigSisterGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🕵️‍♀️ Big Sister – Rule-Based Forensic Analysis")
        self.geometry("1100x700")
        self.minsize(950, 600)
        self.current_file = None
        self.is_dark_mode = False
        self._set_theme()
        self._build_layout()

    def _set_theme(self):
        style = ttk.Style(self)
        style.theme_use("clam")

        if self.is_dark_mode:
            bg = "#2c3e50"
            fg = "#ecf0f1"
            accent = "#3498db"
            font_main = ("Segoe UI", 11)
            font_header = ("Segoe UI Semibold", 18)
            font_subheader = ("Segoe UI", 12)
            text_bg = "#34495e"
            text_fg = "#ecf0f1"
        else:
            bg = "#e6ebf2"
            fg = "#2c3e50"
            accent = "#3498db"
            font_main = ("Segoe UI", 11)
            font_header = ("Segoe UI Semibold", 18)
            font_subheader = ("Segoe UI", 12)
            text_bg = "#ffffff"
            text_fg = "#2c3e50"

        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, font=font_main, foreground=fg)
        style.configure("Header.TLabel", font=font_header, foreground=fg)
        style.configure("SubHeader.TLabel", font=font_subheader, foreground="#7f8c8d")
        style.configure("TButton", font=font_main, padding=8, relief="flat")
        style.map("TButton",
                  background=[('active', accent)],
                  foreground=[('active', '#ffffff')])

        self.textbox_bg = text_bg
        self.textbox_fg = text_fg

    def _build_layout(self):
        # Header
        header = ttk.Frame(self)
        header.pack(fill="x", padx=20, pady=(20, 5))
        ttk.Label(header, text="🕵️ Big Sister", style="Header.TLabel").pack(side="left")
        ttk.Label(header, text="Rule-Based Forensic Analysis", style="SubHeader.TLabel").pack(side="left", padx=15)

        btn_dark_mode = ttk.Button(header, text="🌙 Dark Mode" if not self.is_dark_mode else "🌞 Light Mode", 
                                   command=self.toggle_dark_mode)
        btn_dark_mode.pack(side="right", padx=20)

        # Main paned window
        paned = ttk.PanedWindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True, padx=20, pady=10)

        # Control frame
        ctrl_frame = ttk.Frame(paned, width=270)
        ctrl_frame.pack_propagate(False)
        paned.add(ctrl_frame, weight=1)

        # File selection
        ttk.Label(ctrl_frame, text="📁 Select File", style="SubHeader.TLabel").pack(anchor="w", pady=(10, 5))
        ttk.Button(ctrl_frame, text="Browse...", command=self._browse_file).pack(fill="x")
        self.lbl_file = ttk.Label(ctrl_frame, text="No file selected", wraplength=230)
        self.lbl_file.pack(fill="x", pady=(5, 15))

        ttk.Separator(ctrl_frame).pack(fill="x", pady=10)

        # Single analysis button
        self.btn_analyze = ttk.Button(ctrl_frame, text="🧠 Run Rule-Based Analysis", 
                                      command=self._show_rule_analysis, state="disabled")
        self.btn_analyze.pack(fill="x", pady=4)

        ttk.Separator(ctrl_frame).pack(fill="x", pady=10)

        ttk.Label(ctrl_frame, text="📋 Contributors", style="SubHeader.TLabel").pack(anchor="w", pady=(10, 5))
        ttk.Button(ctrl_frame, text="View Credits", command=self._show_contributors).pack(fill="x")

        # Notebook for tabs
        self.notebook = ttk.Notebook(paned)
        paned.add(self.notebook, weight=4)

        # Add tabs
        self._add_text_tab("Analysis Results", "txt_results")
        self._add_text_tab("Contributors", "txt_contributors")

    def _add_text_tab(self, label, attr_name):
        frame = ttk.Frame(self.notebook)
        textbox = tk.Text(frame, wrap="word", bg=self.textbox_bg, relief="flat", 
                         font=("Consolas", 10), fg=self.textbox_fg)
        textbox.pack(fill="both", expand=True, padx=10, pady=10)
        setattr(self, attr_name, textbox)
        self.notebook.add(frame, text=label)

    def _browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if not path:
            return
        self.current_file = path
        self.lbl_file.config(text=os.path.basename(path))
        self.btn_analyze.state(["!disabled"])

    def _show_rule_analysis(self):
        """Run rule-based analysis and display results"""
        if not self.current_file:
            messagebox.showwarning("No File", "Please select a file first.")
            return

        # Clear previous results
        self.txt_results.config(state="normal")
        self.txt_results.delete("1.0", "end")
        self.txt_results.insert("end", "🔄 Running rule-based analysis...\n\n")
        self.txt_results.config(state="disabled")
        self.notebook.select(self.txt_results.master)

        # Run analysis in background thread
        threading.Thread(
            target=self._perform_rule_analysis,
            args=(self.current_file,),
            daemon=True
        ).start()

    def _perform_rule_analysis(self, file_path: str):
        """Perform rule-based analysis and capture output"""
        try:
            analyzer = FileAnalyzer()
            engine = RuleEngine()
            executor = RuleExecutor()

            mime_type, label = analyzer.analyze(file_path)
            
            output_buffer = StringIO()
            
            output_buffer.write(f"[ File Analysis ]\n")
            output_buffer.write(f"  Path      : {file_path}\n")
            output_buffer.write(f"  MIME Type : {mime_type}\n")
            output_buffer.write(f"  File Type : {label}\n\n")

            rules = engine.get_applicable_rules(mime_type)
            output_buffer.write(f"[ Applicable Rules ]\n")
            if not rules:
                output_buffer.write("  ⚠️  No rules matched this artifact type.\n")
            else:
                for rule in rules:
                    output_buffer.write(f"  - {rule.name}  (priority: {rule.priority})\n")

            combined = {}
            output_buffer.write(f"\n[ Rule Execution ]\n")
            for rule in rules:
                output_buffer.write(f"\n  → {rule.name}\n")
                results = executor.execute_rule(
                    file_path, 
                    rule, 
                    combined, 
                    verbose=True
                )
                combined.update(results)

            output_buffer.write(f"\n{'=' * 60}\n")
            output_buffer.write("Analysis Complete\n")
            output_buffer.write(f"{'=' * 60}\n")
            for k, v in combined.items():
                if k == "extracted_files":
                    output_buffer.write(f"\n  📦 Extracted Files:\n")
                    for extracted in v:
                        output_buffer.write(f"     • {extracted['rel_path']}\n")
                        output_buffer.write(f"       Type: {extracted['type']}\n")
                        output_buffer.write(f"       Path: {extracted['path']}\n")
                else:
                    output_buffer.write(f"  {k:<25}: {v}\n")

            self.after(0, self._display_rule_results, output_buffer.getvalue(), combined)

        except Exception as e:
            error_msg = f"❌ Error during rule analysis: {str(e)}"
            self.after(0, self._display_rule_results, error_msg, {})

    def _display_rule_results(self, results: str, combined: Dict = None):
        """Display rule analysis results in the GUI"""
        self.txt_results.config(state="normal")
        self.txt_results.delete("1.0", "end")
        self.txt_results.insert("end", results)
        
        # Add clickable buttons for extracted files if they exist
        if combined and "extracted_files" in combined:
            self.txt_results.insert("end", "\n" + "=" * 60 + "\n")
            self.txt_results.insert("end", "🖱️  Click to Re-Analyze Extracted Files:\n\n")
            
            for i, extracted in enumerate(combined["extracted_files"]):
                # Insert button as text with tag for styling
                button_text = f"  ▶ {extracted['rel_path']}\n"
                self.txt_results.insert("end", button_text, f"file_{i}")
                # Bind click handler
                self.txt_results.tag_bind(f"file_{i}", "<Button-1>", 
                    lambda e, p=extracted['path']: self._on_extracted_file_click(p))
        
        self.txt_results.config(state="disabled")
    
    def _on_extracted_file_click(self, file_path: str):
        """Handle click on extracted file"""
        self.current_file = file_path
        self.lbl_file.config(text=f"(extracted) {os.path.basename(file_path)}")
        self._show_rule_analysis()

    def toggle_dark_mode(self):
        """Toggle dark/light mode"""
        self.is_dark_mode = not self.is_dark_mode
        self._set_theme()
        self._rebuild_layout()

    def _rebuild_layout(self):
        """Rebuild layout after theme change"""
        file = self.current_file
        for widget in self.winfo_children():
            widget.destroy()
        self._build_layout()
        self.current_file = file
        if self.current_file:
            self.lbl_file.config(text=os.path.basename(file))
            self.btn_analyze.state(["!disabled"])

    def _show_contributors(self):
        """Show project contributors and credits"""
        contributors_text = """🎯 BIG SISTER - Rule-Based Forensic Analysis
═══════════════════════════════════════════════════════════════

👨‍💻 PROJECT CONTRIBUTORS
══════════════════════════

🏆 Project Leader
   • [Your Name] - Project Creator & Maintainer
   • GitHub: @yourusername
   • Role: Core architecture, GUI development

🔧 Main Developers
   • [Vlad-Luca Manolescu] - MaaSec CTF Team member
    • GitHub: https://github.com/IlikeEndermen
    • Tasks: Rule engine implementation, integration and data parsing
   • [Alexia-Madalina Cirstea] - MaaSec CTF Team member
    • GitHub: https://github.com/AlexiaMadalinaCirstea
    • Tasks: Rule-based forensic analysis development


🛠️ TECHNOLOGY STACK
═══════════════════

🖥️ Frontend:
   • Python Tkinter - Cross-platform GUI framework
   • TTK Themes - Modern UI styling

🔍 Analysis Tools:
   • ExifTool - Comprehensive metadata extraction
   • Steghide - Steganography detection and extraction
   • Binwalk - Embedded file signature analysis
   • Zsteg - LSB steganography detection
   • And more...

📊 Data Processing:
   • Rule Engine - YAML-based forensic rules
   • Rule Executor - Orchestrates tool execution
   • File Analyzer - MIME type detection

🏆 PROJECT STATS
════════════════

🎯 Use Cases:
   • CTF Competitions - Image forensics challenges
   • Digital Forensics - File analysis
   • Security Research - Artifact examination

🌍 OPEN SOURCE
══════════════

📜 License: MIT License
🔗 Repository: https://github.com/yourusername/BigSister
🐛 Issues: Report bugs and request features
🤝 Contributions: Pull requests welcome!

═══════════════════════════════════════════════════════════════
        Built with ❤️ by the MaaSec CTF Team
═══════════════════════════════════════════════════════════════"""

        self.txt_contributors.config(state="normal")
        self.txt_contributors.delete("1.0", "end")
        self.txt_contributors.insert("end", contributors_text)
        self.txt_contributors.config(state="disabled")
        self.notebook.select(self.txt_contributors.master)


def startGUI():
    app = BigSisterGUI()
    app.mainloop()


if __name__ == "__main__":
    startGUI()