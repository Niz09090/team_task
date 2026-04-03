# ========================================================
# TIME-BASED LOGIN ALERT TOOL (Task 4)
# ========================================================
# This script creates a complete, interactive GUI tool that:
#   1. Lets you import login logs (CSV format)
#   2. Parses timestamps
#   3. Detects any login attempts between 00:00 and 06:00
#   4. Generates a clear security alert if suspicious night activity is found
#   5. Displays everything in a user-friendly table and alert panel
#
# Requirements: Python 3.6+ (only built-in libraries - no pip install needed)
# ========================================================

import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import csv
from datetime import datetime
import os

# -------------------------------------------------------
# MAIN APPLICATION CLASS
# -------------------------------------------------------
class LoginAlertTool:
    def __init__(self, root):
        """Initialize the GUI window and all widgets."""
        self.root = root
        self.root.title("🛡️ Time-Based Login Alert Tool - Night Activity Detector")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)

        # Storage for loaded log data (list of dictionaries)
        # Each entry = {'timestamp': str, 'username': str, 'ip': str, 'status': str}
        self.log_data = []

        # ---------------------------------------------------
        # TOP BUTTON FRAME
        # ---------------------------------------------------
        # This frame holds the main action buttons
        button_frame = tk.Frame(root, padx=10, pady=10)
        button_frame.pack(fill=tk.X)

        # Button: Import logs
        # Opens a file dialog so user can select a CSV file
        self.import_btn = tk.Button(
            button_frame,
            text="📂 Import Log File (CSV)",
            font=("Arial", 11, "bold"),
            bg="#4CAF50",
            fg="white",
            width=20,
            command=self.import_logs
        )
        self.import_btn.pack(side=tk.LEFT, padx=8)

        # Button: Analyze night logins
        # Runs the detection logic for 00:00–06:00 window
        self.analyze_btn = tk.Button(
            button_frame,
            text="🔍 Analyze Night Logins (00:00-06:00)",
            font=("Arial", 11, "bold"),
            bg="#FF9800",
            fg="white",
            width=28,
            command=self.analyze_night_logins
        )
        self.analyze_btn.pack(side=tk.LEFT, padx=8)

        # Button: Clear everything
        # Resets the tool to start fresh
        self.clear_btn = tk.Button(
            button_frame,
            text="🗑️ Clear All Data",
            font=("Arial", 11, "bold"),
            bg="#f44336",
            fg="white",
            width=18,
            command=self.clear_data
        )
        self.clear_btn.pack(side=tk.LEFT, padx=8)

        # Label showing how many logs are currently loaded
        self.status_label = tk.Label(
            button_frame,
            text="No logs loaded yet",
            font=("Arial", 10),
            fg="#666"
        )
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # ---------------------------------------------------
        # LOG TABLE (Treeview)
        # ---------------------------------------------------
        # This table displays every imported log entry for easy review
        columns = ("Timestamp", "Username", "IP Address", "Status")
        
        self.tree = ttk.Treeview(
            root,
            columns=columns,
            show="headings",
            height=18,
            selectmode="browse"
        )
        
        # Configure column headings and widths
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=180, anchor="w")
        
        # Add vertical scrollbar to the table
        scrollbar = ttk.Scrollbar(root, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack table and scrollbar
        self.tree.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # ---------------------------------------------------
        # ALERT PANEL (bottom)
        # ---------------------------------------------------
        # Large text box where the security alert is displayed
        alert_frame = tk.LabelFrame(root, text="🚨 SECURITY ALERTS", font=("Arial", 12, "bold"), padx=10, pady=5)
        alert_frame.pack(fill=tk.X, padx=10, pady=10)

        self.alert_text = tk.Text(
            alert_frame,
            height=9,
            font=("Consolas", 10),
            bg="#f8f9fa",
            fg="#000",
            state=tk.DISABLED
        )
        self.alert_text.pack(fill=tk.X, padx=5, pady=5)

        # Initial welcome message in the alert panel
        self.show_initial_message()

    # -------------------------------------------------------
    # IMPORT FUNCTION
    # -------------------------------------------------------
    def import_logs(self):
        """Open file dialog and load a CSV log file into memory."""
        file_path = filedialog.askopenfilename(
            title="Select Login Log File",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return  # User clicked Cancel

        try:
            with open(file_path, 'r', newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                
                # Required columns (case-insensitive check)
                fieldnames_lower = [name.lower() for name in reader.fieldnames or []]
                if not all(col in fieldnames_lower for col in ['timestamp', 'username', 'status']):
                    raise ValueError("CSV must contain at least: timestamp, username, status columns")

                # Clear previous data
                self.log_data.clear()

                for row in reader:
                    # Normalize keys to lowercase for robustness
                    ts = row.get('timestamp') or row.get('Timestamp') or ''
                    user = row.get('username') or row.get('Username') or ''
                    ip = row.get('ip_address') or row.get('ip') or row.get('IP') or row.get('Ip') or 'Unknown'
                    status = row.get('status') or row.get('Status') or 'unknown'

                    self.log_data.append({
                        'timestamp': ts.strip(),
                        'username': user.strip(),
                        'ip': ip.strip(),
                        'status': status.strip()
                    })

            # Refresh the table with new data
            self.populate_treeview()
            
            # Update status label
            self.status_label.config(
                text=f"✅ Loaded {len(self.log_data)} entries from: {os.path.basename(file_path)}",
                fg="#2e7d32"
            )
            
            messagebox.showinfo(
                "Import Successful",
                f"Imported {len(self.log_data)} login records.\n\nReady for analysis."
            )

        except Exception as e:
            messagebox.showerror("Import Error", f"Could not read the file:\n{str(e)}")

    # -------------------------------------------------------
    # POPULATE TABLE
    # -------------------------------------------------------
    def populate_treeview(self):
        """Clear the table and insert all loaded log entries."""
        # Remove old rows
        for item in self.tree.get_children():
            self.tree.delete(item)

        # Insert new rows
        for entry in self.log_data:
            self.tree.insert("", tk.END, values=(
                entry['timestamp'],
                entry['username'],
                entry['ip'],
                entry['status']
            ))

    # -------------------------------------------------------
    # ANALYSIS FUNCTION (CORE LOGIC)
    # -------------------------------------------------------
    def analyze_night_logins(self):
        """Detect login attempts between 00:00 and 06:00 and generate alert."""
        if not self.log_data:
            messagebox.showwarning("No Data", "Please import a log file first!")
            return

        night_logins = []
        
        for entry in self.log_data:
            ts_str = entry['timestamp']
            if not ts_str:
                continue  # Skip empty timestamps

            try:
                # Try common timestamp formats
                for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%d/%m/%Y %H:%M:%S', '%d/%m/%Y %H:%M']:
                    try:
                        dt = datetime.strptime(ts_str.strip(), fmt)
                        break
                    except ValueError:
                        continue
                else:
                    continue  # Could not parse this timestamp

                # Check if hour is between 0 and 5 (inclusive)
                if 0 <= dt.hour < 6:
                    night_logins.append({
                        'timestamp': ts_str,
                        'username': entry['username'],
                        'ip': entry['ip'],
                        'status': entry['status'],
                        'hour': dt.hour
                    })
            except Exception:
                # Silently skip unparseable rows (bad data)
                continue

        # Build alert message
        if night_logins:
            alert_title = "🚨 UNUSUAL NIGHT-TIME ACTIVITY DETECTED!"
            alert_body = f"Found {len(night_logins)} login attempt(s) between 00:00 and 06:00.\n\n"
            alert_body += "These attempts occurred during low-activity hours and may indicate:\n"
            alert_body += "• Brute-force attacks\n• Credential stuffing\n• Unauthorized access\n\n"
            alert_body += "Detailed suspicious entries:\n"
            
            for i, login in enumerate(night_logins[:15], 1):  # Show max 15 in alert
                alert_body += f"{i:2d}. {login['timestamp']} | {login['username']} | {login['ip']} | {login['status']}\n"
            
            if len(night_logins) > 15:
                alert_body += f"\n... and {len(night_logins) - 15} more suspicious attempts."
            
            alert_body += "\n\n✅ Recommendation: Immediately investigate these accounts/IPs."
            
            # Show warning popup
            messagebox.showwarning("Security Alert", alert_title)
        else:
            alert_title = "✅ All Clear"
            alert_body = "No login attempts detected between 00:00 and 06:00.\n\nNormal activity pattern confirmed."

        # Display the alert in the bottom text panel
        self.alert_text.config(state=tk.NORMAL)
        self.alert_text.delete(1.0, tk.END)
        self.alert_text.insert(tk.END, alert_body)
        self.alert_text.config(state=tk.DISABLED)

    # -------------------------------------------------------
    # CLEAR FUNCTION
    # -------------------------------------------------------
    def clear_data(self):
        """Reset the entire tool to its initial state."""
        self.log_data.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        self.alert_text.config(state=tk.NORMAL)
        self.alert_text.delete(1.0, tk.END)
        self.alert_text.config(state=tk.DISABLED)
        
        self.status_label.config(text="No logs loaded yet", fg="#666")
        self.show_initial_message()
        
        messagebox.showinfo("Cleared", "All data has been removed.")

    # -------------------------------------------------------
    # HELPER: INITIAL MESSAGE
    # -------------------------------------------------------
    def show_initial_message(self):
        """Show helpful welcome text in the alert panel when starting."""
        self.alert_text.config(state=tk.NORMAL)
        self.alert_text.delete(1.0, tk.END)
        welcome = (
            "👋 Welcome to the Time-Based Login Alert Tool!\n\n"
            "How to use:\n"
            "1. Click 'Import Log File (CSV)'\n"
            "2. Your CSV must have: timestamp, username, status (IP optional)\n"
            "3. Click 'Analyze Night Logins' to scan for 00:00–06:00 activity\n\n"
            "This tool will automatically raise an alert if any logins happened during typical sleeping hours."
        )
        self.alert_text.insert(tk.END, welcome)
        self.alert_text.config(state=tk.DISABLED)


# ========================================================
# RUN THE APPLICATION
# ========================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = LoginAlertTool(root)
    root.mainloop()
