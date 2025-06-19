import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import subprocess
import os

class SignToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Executable Signer")
        self.root.geometry("600x400")
        self.root.resizable(False, False)
        
        # Configure style
        self.style = ttk.Style()
        self.style.configure("TButton", padding=6, relief="flat", background="#ccc")
        self.style.configure("TLabel", padding=6, font=("Arial", 10))
        self.style.configure("TEntry", padding=6)
        
        # Create variables
        self.pfx_file = tk.StringVar()
        self.password = tk.StringVar()
        self.target_file = tk.StringVar()
        self.output_text = tk.StringVar(value="Ready to sign files")
        
        # Create widgets
        self.create_widgets()
        
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # PFX File Selection
        ttk.Label(main_frame, text="Certificate (.pfx):").grid(row=0, column=0, sticky="w", pady=5)
        pfx_frame = ttk.Frame(main_frame)
        pfx_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5)
        
        ttk.Entry(pfx_frame, textvariable=self.pfx_file, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(pfx_frame, text="Browse", command=self.browse_pfx).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Password
        ttk.Label(main_frame, text="Password:").grid(row=2, column=0, sticky="w", pady=5)
        ttk.Entry(main_frame, textvariable=self.password, show="*", width=58).grid(row=3, column=0, sticky="ew", pady=5)
        
        # Target File Selection
        ttk.Label(main_frame, text="File to Sign:").grid(row=4, column=0, sticky="w", pady=5)
        target_frame = ttk.Frame(main_frame)
        target_frame.grid(row=5, column=0, columnspan=2, sticky="ew", pady=5)
        
        ttk.Entry(target_frame, textvariable=self.target_file, width=50).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(target_frame, text="Browse", command=self.browse_target).pack(side=tk.RIGHT, padx=(5, 0))
        
        # Sign Button
        ttk.Button(main_frame, text="Sign Executable", command=self.sign_file, style="Accent.TButton").grid(row=6, column=0, pady=20)
        
        # Output Log
        ttk.Label(main_frame, text="Output:").grid(row=7, column=0, sticky="w", pady=5)
        output_frame = ttk.Frame(main_frame)
        output_frame.grid(row=8, column=0, sticky="nsew")
        
        self.output_area = tk.Text(output_frame, height=8, width=70, bg="#f0f0f0", relief="solid", borderwidth=1)
        scrollbar = ttk.Scrollbar(output_frame, command=self.output_area.yview)
        self.output_area.configure(yscrollcommand=scrollbar.set)
        
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.output_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.output_area.insert(tk.END, "Ready to sign files\n")
        self.output_area.config(state=tk.DISABLED)
        
        # Configure styles for colored buttons
        self.style.configure("Accent.TButton", background="#4CAF50", foreground="white", font=("Arial", 10, "bold"))
        
    def browse_pfx(self):
        file_path = filedialog.askopenfilename(
            title="Select PFX Certificate",
            filetypes=[("PFX Files", "*.pfx"), ("All Files", "*.*")]
        )
        if file_path:
            self.pfx_file.set(file_path)
            
    def browse_target(self):
        file_path = filedialog.askopenfilename(
            title="Select File to Sign",
            filetypes=[("Executable Files", "*.exe"), ("All Files", "*.*")]
        )
        if file_path:
            self.target_file.set(file_path)
            
    def sign_file(self):
        pfx = self.pfx_file.get()
        password = self.password.get()
        target = self.target_file.get()
        
        # Validate inputs
        if not all([pfx, password, target]):
            messagebox.showerror("Error", "All fields are required!")
            return
            
        if not os.path.exists(pfx):
            messagebox.showerror("Error", "PFX file does not exist!")
            return
            
        if not os.path.exists(target):
            messagebox.showerror("Error", "Target file does not exist!")
            return
            
        # Build command
        cmd = [
            "signtool.exe", "sign",
            "/f", pfx,
            "/p", password,
            "/fd", "sha256",
            "/t", "http://timestamp.digicert.com",
            target
        ]
        
        # Display command in output
        self.output_area.config(state=tk.NORMAL)
        self.output_area.insert(tk.END, "\nSigning command:\n")
        self.output_area.insert(tk.END, " ".join(cmd) + "\n")
        self.output_area.insert(tk.END, "Working... ")
        self.output_area.see(tk.END)
        self.output_area.config(state=tk.DISABLED)
        self.root.update()
        
        try:
            # Run signing command
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            
            # Show success
            self.output_area.config(state=tk.NORMAL)
            self.output_area.insert(tk.END, "SUCCESS!\n")
            self.output_area.insert(tk.END, result.stdout + "\n")
            self.output_area.see(tk.END)
            self.output_area.config(state=tk.DISABLED)
            
            messagebox.showinfo("Success", "File signed successfully!")
            
        except subprocess.CalledProcessError as e:
            # Show error
            self.output_area.config(state=tk.NORMAL)
            self.output_area.insert(tk.END, "FAILED!\n")
            self.output_area.insert(tk.END, f"Error: {e.stderr}\n")
            self.output_area.see(tk.END)
            self.output_area.config(state=tk.DISABLED)
            
            messagebox.showerror("Signing Error", f"Signing failed:\n{e.stderr}")

if __name__ == "__main__":
    root = tk.Tk()
    app = SignToolGUI(root)
    root.mainloop()