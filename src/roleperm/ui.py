from __future__ import annotations

from typing import Optional

from .auth import Role, authenticate, DEFAULT_ROLES_FILE


def login_popup(*, title: str = "Login", roles_file: str = DEFAULT_ROLES_FILE, logo_text: Optional[str] = None) -> Role:
    """
    Tkinter login popup. Returns a Role on success.
    Raises ValueError on failed login, but UI keeps the user in the window until success or close.

    If the user closes the window, raises PermissionError("Login cancelled.").
    """
    try:
        import tkinter as tk
        from tkinter import messagebox
    except Exception as e:  # pragma: no cover
        raise RuntimeError("Tkinter is not available in this Python environment.") from e

    result = {"role": None}

    root = tk.Tk()
    root.title(title)
    root.resizable(False, False)

    frame = tk.Frame(root, padx=14, pady=14)
    frame.pack()

    row = 0
    if logo_text:
        tk.Label(frame, text=logo_text, font=("Arial", 14, "bold")).grid(row=row, column=0, columnspan=2, pady=(0, 10))
        row += 1

    tk.Label(frame, text="Username").grid(row=row, column=0, sticky="e", padx=(0, 8), pady=4)
    username = tk.Entry(frame, width=28)
    username.grid(row=row, column=1, pady=4)
    row += 1

    tk.Label(frame, text="Password").grid(row=row, column=0, sticky="e", padx=(0, 8), pady=4)
    password = tk.Entry(frame, width=28, show="*")
    password.grid(row=row, column=1, pady=4)
    row += 1

    def submit() -> None:
        u = username.get().strip()
        p = password.get()
        try:
            role = authenticate(u, p, roles_file=roles_file)
            result["role"] = role
            root.destroy()
        except ValueError as err:
            messagebox.showerror("Login failed", str(err))

    def on_close() -> None:
        root.destroy()

    btn = tk.Button(frame, text="Login", command=submit, width=12)
    btn.grid(row=row, column=0, columnspan=2, pady=(10, 0))

    username.focus_set()
    root.bind("<Return>", lambda _e: submit())
    root.protocol("WM_DELETE_WINDOW", on_close)

    root.mainloop()

    if result["role"] is None:
        raise PermissionError("Login cancelled.")
    return result["role"]
