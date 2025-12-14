from __future__ import annotations

from typing import Optional
from .auth import authenticate, DEFAULT_ROLES_FILE, Role, _set_session

def login(*, title: str = "Login", roles_file: str = DEFAULT_ROLES_FILE, logo_text: Optional[str] = None) -> Role:
    import tkinter as tk
    from tkinter import messagebox

    result = {"role": None}
    root = tk.Tk()
    root.title(title)
    root.resizable(False, False)

    frame = tk.Frame(root, padx=14, pady=14)
    frame.pack()

    if logo_text:
        tk.Label(frame, text=logo_text, font=("Arial", 14, "bold")).grid(row=0, column=0, columnspan=2, pady=(0, 10))

    tk.Label(frame, text="Username").grid(row=1, column=0, sticky="e", padx=(0, 8), pady=4)
    username = tk.Entry(frame, width=28)
    username.grid(row=1, column=1, pady=4)

    tk.Label(frame, text="Password").grid(row=2, column=0, sticky="e", padx=(0, 8), pady=4)
    password = tk.Entry(frame, width=28, show="*")
    password.grid(row=2, column=1, pady=4)

    def submit():
        u = username.get().strip()
        p = password.get()
        try:
            role = authenticate(u, p, roles_file=roles_file)
            _set_session(role)
            result["role"] = role
            root.destroy()
        except ValueError as e:
            messagebox.showerror("Login failed", str(e))

    tk.Button(frame, text="Login", command=submit, width=12).grid(row=3, column=0, columnspan=2, pady=(10, 0))
    username.focus_set()
    root.bind("<Return>", lambda _e: submit())

    root.mainloop()
    if result["role"] is None:
        raise PermissionError("Login cancelled.")
    return result["role"]
