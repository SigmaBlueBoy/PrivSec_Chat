import tkinter as tk
from tkinter import messagebox, scrolledtext, filedialog
from PIL import Image, ImageTk
import sqlite3
import hashlib
import random
import string
import socket
import threading
import json
import base64
import io
import uuid
import os

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect('privsec_local.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (username TEXT PRIMARY KEY, pass_hash TEXT, auth_code TEXT)''')
    conn.commit()
    conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def generate_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))

# --- Network Setup (LAN P2P) ---
PORT = 55555
peers = []
DELIMITER = "___PRIVSEC_END_OF_MSG___"
MY_CLIENT_ID = str(uuid.uuid4())
SEEN_MESSAGE_IDS = set()

def start_server(app_instance):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.bind(('0.0.0.0', PORT))
        server.listen(5)
    except Exception as e:
        print(f"Server bind error: {e}")
        return
    
    while True:
        try:
            client, addr = server.accept()
            peers.append(client)
            threading.Thread(target=handle_client, args=(client, app_instance), daemon=True).start()
        except Exception:
            break

def handle_client(client, app_instance):
    buffer = ""
    while True:
        try:
            data = client.recv(65536).decode('utf-8', errors='ignore')
            if not data:
                if client in peers:
                    peers.remove(client)
                client.close()
                break
            
            buffer += data
            while DELIMITER in buffer:
                message, buffer = buffer.split(DELIMITER, 1)
                message = message.strip()
                if message:
                    try:
                        payload = json.loads(message)
                        msg_id = payload.get('msg_id')

                        # Drop if already seen
                        if msg_id and msg_id in SEEN_MESSAGE_IDS:
                            continue

                        if msg_id:
                            SEEN_MESSAGE_IDS.add(msg_id)

                        # Only display if it didn't originate from ourselves
                        if payload.get('client_id') != MY_CLIENT_ID:
                            app_instance.display_data(payload)

                        # Re-broadcast on separate thread to prevent blocking incoming socket
                        threading.Thread(target=broadcast_data, args=(payload, client), daemon=True).start()

                    except json.JSONDecodeError:
                        # CRITICAL FIX: If buffer gets corrupted, CLEAR IT to stop infinite spam loop
                        buffer = ""
                        break
        except Exception:
            if client in peers:
                peers.remove(client)
            client.close()
            break

def broadcast_data(payload, exclude_client=None):
    data = json.dumps(payload) + DELIMITER
    encoded_data = data.encode('utf-8')
    for peer in list(peers):
        if peer == exclude_client:
            continue
        try:
            peer.sendall(encoded_data)
        except Exception:
            if peer in peers:
                peers.remove(peer)
            peer.close()

# --- UI and Application Logic ---
class PrivSecApp:
    def __init__(self, root):
        self.root = root
        self.root.title("PrivSec Connect")
        self.root.geometry("520x700")
        self.root.configure(bg="#0a0a0a")
        
        if os.path.exists("logo.ico"):
            try:
                self.root.iconbitmap("logo.ico")
            except Exception:
                pass

        self.current_user = None
        self.current_channel = "General"
        self.image_references = []

        self.setup_login_screen()
        threading.Thread(target=start_server, args=(self,), daemon=True).start()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def setup_login_screen(self):
        self.clear_window()
        
        tk.Label(self.root, text="PrivSec", font=("Arial", 26, "bold"), bg="#0a0a0a", fg="#ffffff").pack(pady=30)
        
        tk.Label(self.root, text="Username:", bg="#0a0a0a", fg="#ffffff").pack()
        self.entry_user = tk.Entry(self.root, bg="#1a1a1a", fg="#ffffff", insertbackground="white", width=30)
        self.entry_user.pack(pady=5)

        tk.Label(self.root, text="Password:", bg="#0a0a0a", fg="#ffffff").pack()
        self.entry_pass = tk.Entry(self.root, show="*", bg="#1a1a1a", fg="#ffffff", insertbackground="white", width=30)
        self.entry_pass.pack(pady=5)

        tk.Label(self.root, text="Auth Code (Required for Login):", bg="#0a0a0a", fg="#ffffff").pack()
        self.entry_code = tk.Entry(self.root, bg="#1a1a1a", fg="#ffffff", insertbackground="white", width=30)
        self.entry_code.pack(pady=5)

        tk.Button(self.root, text="Login", command=self.login, bg="#333333", fg="#ffffff", width=22).pack(pady=12)
        tk.Button(self.root, text="Sign Up (Generate Code)", command=self.signup, bg="#333333", fg="#ffffff", width=22).pack()

    def signup(self):
        user = self.entry_user.get().strip()
        pwd = self.entry_pass.get().strip()
        
        if not user or not pwd:
            messagebox.showerror("Error", "Username and Password are required to sign up.")
            return

        conn = sqlite3.connect('privsec_local.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username=?", (user,))
        if c.fetchone():
            messagebox.showerror("Error", "Username already exists.")
            conn.close()
            return

        code = generate_code()
        c.execute("INSERT INTO users VALUES (?, ?, ?)", (user, hash_password(pwd), code))
        conn.commit()
        conn.close()

        messagebox.showinfo("Auth Code Generated", f"Save this authentication code. You must enter it every time you log in:\n\n{code}")

    def login(self):
        user = self.entry_user.get().strip()
        pwd = self.entry_pass.get().strip()
        code = self.entry_code.get().strip()

        if not user or not pwd or not code:
            messagebox.showerror("Error", "Username, Password, and Auth Code are all required to log in.")
            return

        conn = sqlite3.connect('privsec_local.db')
        c = conn.cursor()
        c.execute("SELECT pass_hash, auth_code FROM users WHERE username=?", (user,))
        result = c.fetchone()
        conn.close()

        if not result:
            messagebox.showerror("Error", "Username not found.")
            return

        stored_hash, stored_code = result

        if hash_password(pwd) != stored_hash:
            messagebox.showerror("Error", "Incorrect Password.")
        elif code != stored_code:
            messagebox.showerror("Error", "Invalid Auth Code. Please check the code generated during sign up.")
        else:
            self.current_user = user
            self.setup_chat_screen()

    def setup_chat_screen(self):
        self.clear_window()
        
        top_frame = tk.Frame(self.root, bg="#0a0a0a")
        top_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(top_frame, text="General", command=lambda: self.switch_channel("General"), bg="#333333", fg="#ffffff", width=12).pack(side=tk.LEFT, padx=15)
        tk.Button(top_frame, text="Announcements", command=lambda: self.switch_channel("Announcements"), bg="#333333", fg="#ffffff", width=15).pack(side=tk.LEFT)
        
        self.current_channel = "General"
        
        conn_frame = tk.Frame(self.root, bg="#0a0a0a")
        conn_frame.pack(fill=tk.X, padx=15, pady=5)
        
        tk.Label(conn_frame, text="Connect Peer IP:", bg="#0a0a0a", fg="#ffffff").pack(side=tk.LEFT)
        self.entry_ip = tk.Entry(conn_frame, bg="#1a1a1a", fg="#ffffff", insertbackground="white")
        self.entry_ip.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        tk.Button(conn_frame, text="Connect", command=self.connect_to_peer, bg="#333333", fg="#ffffff").pack(side=tk.LEFT)

        self.chat_display = scrolledtext.ScrolledText(self.root, state='disabled', bg="#1a1a1a", fg="#ffffff", wrap=tk.WORD)
        self.chat_display.pack(padx=15, pady=10, fill=tk.BOTH, expand=True)

        self.entry_msg = tk.Entry(self.root, bg="#1a1a1a", fg="#ffffff", insertbackground="white")
        self.entry_msg.pack(fill=tk.X, padx=15, pady=5)
        
        btn_frame = tk.Frame(self.root, bg="#0a0a0a")
        btn_frame.pack(pady=10)
        
        tk.Button(btn_frame, text="Send Text", command=self.send_message, bg="#333333", fg="#ffffff", width=12).pack(side=tk.LEFT, padx=5)
        tk.Button(btn_frame, text="Send Image", command=self.send_image, bg="#333333", fg="#ffffff", width=12).pack(side=tk.LEFT, padx=5)

    def switch_channel(self, channel_name):
        self.current_channel = channel_name
        self.chat_display.config(state='normal')
        self.chat_display.insert(tk.END, f"\n--- Switched to {channel_name} ---\n")
        self.chat_display.config(state='disabled')
        self.chat_display.yview(tk.END)

    def connect_to_peer(self):
        ip = self.entry_ip.get().strip()
        if not ip:
            messagebox.showerror("Error", "Enter an IP address.")
            return
        try:
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client.connect((ip, PORT))
            peers.append(client)
            threading.Thread(target=handle_client, args=(client, self), daemon=True).start()
            messagebox.showinfo("Success", f"Connected to peer at {ip}")
        except Exception as e:
            messagebox.showerror("Connection Failed", f"Could not connect to {ip}: {e}")

    def send_message(self):
        msg = self.entry_msg.get().strip()
        if not msg:
            return

        if self.current_channel == "Announcements" and self.current_user != "BlueBoy":
            messagebox.showwarning("Access Denied", "Only BlueBoy is authorized to post in Announcements.")
            return

        msg_id = str(uuid.uuid4())
        SEEN_MESSAGE_IDS.add(msg_id)

        payload = {
            'msg_id': msg_id,
            'client_id': MY_CLIENT_ID,
            'type': 'text', 
            'channel': self.current_channel, 
            'sender': self.current_user, 
            'content': msg
        }
        self.entry_msg.delete(0, tk.END)
        self.display_data(payload)
        threading.Thread(target=broadcast_data, args=(payload,), daemon=True).start()

    def send_image(self):
        if self.current_channel == "Announcements" and self.current_user != "BlueBoy":
            messagebox.showwarning("Access Denied", "Only BlueBoy is authorized to post in Announcements.")
            return

        file_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png *.jpg *.jpeg *.gif *.bmp")])
        if not file_path:
            return

        try:
            with open(file_path, "rb") as image_file:
                img = Image.open(image_file)
                # Resizes image to keep byte payload lean and safe over LAN sockets
                img.thumbnail((300, 300))
                buffered = io.BytesIO()
                img.save(buffered, format="PNG")
                encoded_string = base64.b64encode(buffered.getvalue()).decode('utf-8')
            
            msg_id = str(uuid.uuid4())
            SEEN_MESSAGE_IDS.add(msg_id)

            payload = {
                'msg_id': msg_id,
                'client_id': MY_CLIENT_ID,
                'type': 'image', 
                'channel': self.current_channel, 
                'sender': self.current_user, 
                'content': encoded_string
            }
            self.display_data(payload)
            threading.Thread(target=broadcast_data, args=(payload,), daemon=True).start()
        except Exception as e:
            messagebox.showerror("Error", f"Could not load image: {e}")

    def display_data(self, data):
        if data['channel'] == self.current_channel:
            self.chat_display.config(state='normal')
            self.chat_display.insert(tk.END, f"[{data['sender']}]: ")
            
            if data['type'] == 'text':
                self.chat_display.insert(tk.END, f"{data['content']}\n")
            elif data['type'] == 'image':
                try:
                    raw_data = base64.b64decode(data['content'])
                    img = Image.open(io.BytesIO(raw_data))
                    photo = ImageTk.PhotoImage(img)
                    
                    self.image_references.append(photo)
                    
                    self.chat_display.insert(tk.END, "\n")
                    self.chat_display.image_create(tk.END, image=photo)
                    self.chat_display.insert(tk.END, "\n")
                except Exception as e:
                    self.chat_display.insert(tk.END, f"[Failed to load image: {e}]\n")

            self.chat_display.config(state='disabled')
            self.chat_display.yview(tk.END)

if __name__ == "__main__":
    init_db()
    root = tk.Tk()
    app = PrivSecApp(root)
    root.mainloop()