# ========================================================
# CUSTOM WORDLIST GENERATOR (OSINT ƏSASLI)
# ========================================================
# This tool generates targeted password wordlists based on 
# personal information collected through OSINT.
# 
# Perfect for security testing, password auditing, and training.
# Supports common patterns people actually use in passwords.
# ========================================================

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import itertools
import string
from datetime import datetime
import os

class OSINTWordlistGenerator:
    def __init__(self, root):
        self.root = root
        self.root.title("🔑 Custom Wordlist Generator (OSINT əsaslı)")
        self.root.geometry("950x720")
        self.root.resizable(True, True)

        self.wordlist = []

        # ------------------- Input Frame -------------------
        input_frame = tk.LabelFrame(root, text="👤 OSINT-dən əldə edilmiş məlumatlar", font=("Arial", 12, "bold"), padx=15, pady=15)
        input_frame.pack(fill=tk.X, padx=15, pady=10)

        # Row 1
        tk.Label(input_frame, text="Ad / First Name:").grid(row=0, column=0, sticky="w", pady=4)
        self.first_name = tk.Entry(input_frame, width=30)
        self.first_name.grid(row=0, column=1, pady=4, padx=10)

        tk.Label(input_frame, text="Soyad / Surname:").grid(row=0, column=2, sticky="w", pady=4)
        self.last_name = tk.Entry(input_frame, width=30)
        self.last_name.grid(row=0, column=3, pady=4, padx=10)

        # Row 2
        tk.Label(input_frame, text="Ləqəb / Nickname:").grid(row=1, column=0, sticky="w", pady=4)
        self.nickname = tk.Entry(input_frame, width=30)
        self.nickname.grid(row=1, column=1, pady=4, padx=10)

        tk.Label(input_frame, text="Doğum tarixi (DDMMYYYY):").grid(row=1, column=2, sticky="w", pady=4)
        self.birthdate = tk.Entry(input_frame, width=30)
        self.birthdate.grid(row=1, column=3, pady=4, padx=10)

        # Row 3
        tk.Label(input_frame, text="Partnyor adı:").grid(row=2, column=0, sticky="w", pady=4)
        self.partner = tk.Entry(input_frame, width=30)
        self.partner.grid(row=2, column=1, pady=4, padx=10)

        tk.Label(input_frame, text="Ev heyvanı adı / Pet:").grid(row=2, column=2, sticky="w", pady=4)
        self.pet = tk.Entry(input_frame, width=30)
        self.pet.grid(row=2, column=3, pady=4, padx=10)

        # Row 4
        tk.Label(input_frame, text="Şirkət / Company:").grid(row=3, column=0, sticky="w", pady=4)
        self.company = tk.Entry(input_frame, width=30)
        self.company.grid(row=3, column=1, pady=4, padx=10)

        tk.Label(input_frame, text="Sevimli rəqəm / Favorite Number:").grid(row=3, column=2, sticky="w", pady=4)
        self.fav_number = tk.Entry(input_frame, width=30)
        self.fav_number.grid(row=3, column=3, pady=4, padx=10)

        # ------------------- Options -------------------
        options_frame = tk.LabelFrame(root, text="⚙️ Əlavə seçimlər", font=("Arial", 11, "bold"), padx=15, pady=10)
        options_frame.pack(fill=tk.X, padx=15, pady=8)

        self.include_leet = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Leetspeak istifadə et (a→@, e→3, i→1 ...)", variable=self.include_leet).pack(anchor="w")

        self.include_symbols = tk.BooleanVar(value=True)
        tk.Checkbutton(options_frame, text="Simvollar əlavə et (! @ # $ _ -)", variable=self.include_symbols).pack(anchor="w")

        self.max_length = tk.IntVar(value=16)
        tk.Label(options_frame, text="Maksimum uzunluq:").pack(anchor="w", side=tk.LEFT, padx=(0,5))
        tk.Spinbox(options_frame, from_=8, to=30, textvariable=self.max_length, width=5).pack(anchor="w", side=tk.LEFT)

        # ------------------- Buttons -------------------
        btn_frame = tk.Frame(root, pady=12)
        btn_frame.pack()

        tk.Button(btn_frame, text="🚀 Wordlist Yarat", font=("Arial", 12, "bold"), bg="#4CAF50", fg="white", width=20,
                  command=self.generate_wordlist).pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="💾 Fayla Saxla (.txt)", font=("Arial", 12, "bold"), bg="#2196F3", fg="white", width=20,
                  command=self.save_wordlist).pack(side=tk.LEFT, padx=10)

        tk.Button(btn_frame, text="🗑️ Təmizlə", font=("Arial", 12, "bold"), bg="#f44336", fg="white", width=15,
                  command=self.clear_all).pack(side=tk.LEFT, padx=10)

        # ------------------- Status & Result -------------------
        self.status_label = tk.Label(root, text="Hazırdır. Məlumatları doldurun və 'Wordlist Yarat' düyməsini basın.", fg="#555", font=("Arial", 10))
        self.status_label.pack(pady=8)

        result_frame = tk.LabelFrame(root, text="📊 Nəticə", font=("Arial", 11, "bold"), padx=10, pady=10)
        result_frame.pack(fill=tk.BOTH, expand=True, padx=15, pady=10)

        self.result_text = tk.Text(result_frame, height=18, font=("Consolas", 10))
        scrollbar = ttk.Scrollbar(result_frame, orient="vertical", command=self.result_text.yview)
        self.result_text.configure(yscrollcommand=scrollbar.set)

        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    def generate_wordlist(self):
        """Generate targeted wordlist from OSINT data."""
        base_words = []

        # Collect base information
        fields = [
            self.first_name.get().strip(),
            self.last_name.get().strip(),
            self.nickname.get().strip(),
            self.partner.get().strip(),
            self.pet.get().strip(),
            self.company.get().strip()
        ]

        for f in fields:
            if f:
                base_words.append(f.lower())
                base_words.append(f.capitalize())

        # Birthdate processing
        birth = self.birthdate.get().strip()
        if len(birth) == 8 and birth.isdigit():
            day = birth[0:2]
            month = birth[2:4]
            year = birth[4:8]
            base_words.extend([day, month, year, year[-2:], day+month, month+year, year+day])

        # Favorite number
        fav = self.fav_number.get().strip()
        if fav:
            base_words.append(fav)

        if not base_words:
            messagebox.showwarning("Xəta", "Ən azı bir sahəni doldurun!")
            return

        # Start generating
        self.wordlist = set()  # avoid duplicates

        # Base words
        for word in base_words:
            if 4 <= len(word) <= self.max_length.get():
                self.wordlist.add(word)

        # Common combinations
        for a, b in itertools.product(base_words, repeat=2):
            if a != b:
                combo = a + b
                if len(combo) <= self.max_length.get():
                    self.wordlist.add(combo)
                if self.include_symbols.get():
                    for sym in ["", "_", "-", "!", "@", "#", "$"]:
                        self.wordlist.add(a + sym + b)

        # Date + name patterns
        if birth and len(birth) == 8:
            year = birth[4:8]
            for name in base_words[:5]:  # limit
                for y in [year, year[-2:]]:
                    self.wordlist.add(name + y)
                    self.wordlist.add(name.capitalize() + y)
                    if self.include_symbols.get():
                        self.wordlist.add(name + y + "!")
                        self.wordlist.add(name + "_" + y)

        # Simple leetspeak (basic version)
        if self.include_leet.get():
            leet_map = {'a':'@', 'e':'3', 'i':'1', 'o':'0', 's':'5', 't':'7'}
            new_set = set()
            for w in list(self.wordlist):
                for orig, repl in leet_map.items():
                    if orig in w:
                        new_w = w.replace(orig, repl)
                        new_set.add(new_w)
                        new_set.add(new_w.capitalize())
            self.wordlist.update(new_set)

        # Final cleanup
        final_list = sorted([w for w in self.wordlist if 6 <= len(w) <= self.max_length.get()])

        # Show result
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"✅ Uğurla yaradıldı! Toplam söz sayı: {len(final_list)}\n\n")
        self.result_text.insert(tk.END, "\n".join(final_list[:300]))  # Show first 300 only in GUI

        if len(final_list) > 300:
            self.result_text.insert(tk.END, f"\n\n... və daha {len(final_list)-300} söz (faylda tam görünəcək)")

        self.status_label.config(text=f"✅ {len(final_list)} söz yaradıldı. Saxlamaq üçün düyməyə basın.", fg="green")

    def save_wordlist(self):
        """Save generated wordlist to file."""
        if not self.wordlist:
            messagebox.showwarning("Xəta", "Əvvəlcə wordlist yaradın!")
            return

        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            initialfile=f"target_wordlist_{datetime.now().strftime('%Y%m%d')}.txt"
        )

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as f:
                    f.write("\n".join(sorted(self.wordlist)))
                messagebox.showinfo("Uğurlu", f"Wordlist saxlanıldı:\n{file_path}\n\nToplam söz: {len(self.wordlist)}")
            except Exception as e:
                messagebox.showerror("Xəta", str(e))

    def clear_all(self):
        """Clear all fields and results."""
        for widget in [self.first_name, self.last_name, self.nickname, self.birthdate,
                       self.partner, self.pet, self.company, self.fav_number]:
            widget.delete(0, tk.END)
        
        self.result_text.delete(1.0, tk.END)
        self.wordlist.clear()
        self.status_label.config(text="Təmizləndi. Yenidən məlumat daxil edin.", fg="#555")


# ========================================================
# RUN THE TOOL
# ========================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = OSINTWordlistGenerator(root)
    root.mainloop()
