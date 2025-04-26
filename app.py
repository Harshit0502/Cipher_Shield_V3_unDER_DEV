import streamlit as st
import requests
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
import time
# ------------------- CONFIG -------------------
BACKEND_URL = "https://cipher-shield-v3-under-dev.onrender.com"
# Example: http://127.0.0.1:8000 or deployed backend URL

# ------------------- SESSION STATE -------------------
if 'token' not in st.session_state:
    st.session_state.token = None
if 'private_key' not in st.session_state:
    st.session_state.private_key = None
if 'username' not in st.session_state:
    st.session_state.username = None

# ------------------- AUTH FUNCTIONS -------------------
def signup(username, email, password):
    url = f"{BACKEND_URL}/auth/signup/"
    data = {'username': username, 'email': email, 'password': password}
    response = requests.post(url, json=data)
    return response

def login(username, password):
    url = f"{BACKEND_URL}/auth/login/"
    data = {'username': username, 'password': password}
    response = requests.post(url, json=data)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def fetch_private_key(username):
    # For demo, fetching private key insecurely (In production: use encrypted download)
    url = f"{BACKEND_URL}/auth/private_key/{username}/"
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    response = requests.get(url, headers=headers)
    return response.text

# ------------------- CHAT FUNCTIONS -------------------
def send_message(receiver, plain_text):
    url = f"{BACKEND_URL}/chat/send/"
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    data = {'receiver': receiver, 'plain_text': plain_text}
    response = requests.post(url, headers=headers, json=data)
    return response

def get_chat_history(other_user):
    url = f"{BACKEND_URL}/chat/history/?with={other_user}"
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    return []

def decrypt_message(encrypted_hex, private_key_pem):
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None,
    )
    encrypted_bytes = bytes.fromhex(encrypted_hex)
    plaintext = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return plaintext.decode()

def encrypt_message(plain_text, public_key_pem):
    public_key = serialization.load_pem_public_key(
        public_key_pem.encode()
    )
    ciphertext = public_key.encrypt(
        plain_text.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext.hex()

def fetch_public_key(username):
    url = f"{BACKEND_URL}/auth/public_key/{username}/"
    headers = {"Authorization": f"Bearer {st.session_state.token}"}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.text
    else:
        st.error("Failed to fetch receiver's public key.")
        return None

# ------------------- STREAMLIT UI -------------------
st.title("🔐 Cipher Shield - Secure Chat")

if not st.session_state.token:
    st.subheader("Login / Signup")

    tab1, tab2 = st.tabs(["Login", "Signup"])

    with tab1:
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        if st.button("Login"):
            auth_data = login(username, password)
            if auth_data:
                st.success("Login successful!")
                st.session_state.token = auth_data['access']
                st.session_state.username = username
                # ------------------------ FETCH PRIVATE KEY ------------------------
                private_key = fetch_private_key(username)
                if private_key:
                    st.session_state.private_key = private_key
                    st.success("Private key loaded successfully!")
                else:
                    st.warning("Private key could not be fetched.")

            else:
                st.error("Login failed.")

    with tab2:
        username = st.text_input("New Username")
        email = st.text_input("Email")
        password = st.text_input("New Password", type="password")
        if st.button("Signup"):
            resp = signup(username, email, password)
            if resp.status_code == 201:
                st.success("Signup successful! Please login.")
            else:
                st.error(f"Signup failed: {resp.text}")

else:
    st.sidebar.title(f"Welcome, {st.session_state.username} 👋")
    st.sidebar.subheader("Chat with Someone:")

    receiver_username = st.sidebar.text_input("Receiver Username")
    message_text = st.sidebar.text_input("Your Message")
    if st.sidebar.button("Send Message"):
        if receiver_username and message_text:
            receiver_public_key_pem = fetch_public_key(receiver_username)
            if receiver_public_key_pem:
                encrypted_text = encrypt_message(message_text, receiver_public_key_pem)
                send_response = send_message(receiver_username, encrypted_text)
                if send_response.status_code == 201:
                    st.sidebar.success("Message Sent!")
                else:
                    st.sidebar.error("Failed to send message.")


    st.subheader("💬 Chat History")
    target_user = st.text_input("Chatting with (username)")
    st.subheader("💬 Live Chat with Another Soldier")
    if target_user:
        chat_area = st.empty()
        while True:
            chats = get_chat_history(target_user)
            with chat_area.container():
                st.write("---")  # Line separator
                if chats:
                    for chat in chats:
                        sender = chat['sender']
                        encrypted_text = chat['encrypted_text']
                        timestamp = chat.get('timestamp', 'Unknown Time')

                        # Identify if it's your message or enemy's
                        if sender == st.session_state.username:
                            st.success(f"🧑‍💻 You ({timestamp}):\n{encrypted_text}")
                        else:
                            try:
                                decrypted_text = decrypt_message(encrypted_text, st.session_state.private_key)
                                st.info(f"👥 {sender} ({timestamp}):\n{decrypted_text}")
                            except Exception as e:
                                st.error("⚠️ Decryption failed.")
                else:
                    st.info("No chats yet, start sending messages!")

            time.sleep(5)  # Refresh every 5 sec
            st.experimental_rerun()

    if st.button("Logout"):
        st.session_state.token = None
        st.session_state.private_key = None
        st.session_state.username = None
        st.success("Logged out successfully!")

