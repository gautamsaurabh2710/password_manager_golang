import React from "react";
import { createRoot } from "react-dom/client";
import {
  KeyRound,
  Lock,
  LogOut,
  Mail,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  User,
  Globe,
  Eye,
  EyeOff,
  Pencil,
  Save,
  X,
} from "lucide-react";
import "./styles.css";

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:5000";

function App() {
  const [token, setToken] = React.useState(() => localStorage.getItem("token") || "");
  const [emailForOtp, setEmailForOtp] = React.useState("");
  const [mode, setMode] = React.useState("login");
  const [message, setMessage] = React.useState("");
  const [loading, setLoading] = React.useState(false);
  const [passwords, setPasswords] = React.useState([]);
  const [transportPublicKey, setTransportPublicKey] = React.useState("");
  const [securityKeyReady, setSecurityKeyReady] = React.useState(false);

  async function apiRequest(path, options = {}) {
    const response = await fetch(`${API_BASE_URL}${path}`, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...options.headers,
      },
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.message || data.error || "Something went wrong");
    }
    return data;
  }

  function saveToken(newToken) {
    localStorage.setItem("token", newToken);
    setToken(newToken);
    setMessage("Login successful");
  }

  async function encryptForServer(value) {
    const publicKey = transportPublicKey || await loadPublicKey();
    return encryptWithPublicKey(publicKey, value);
  }

  function logout() {
    localStorage.removeItem("token");
    setToken("");
    setPasswords([]);
    setMessage("Logged out successfully");
  }

  async function loadPasswords() {
    setLoading(true);
    setMessage("");
    try {
      const data = await apiRequest("/api/passwords");
      setPasswords(Array.isArray(data) ? data : []);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => {
    loadPublicKey();
  }, []);

  async function loadPublicKey() {
    try {
      const response = await fetch(`${API_BASE_URL}/api/security/public-key`);
      const data = await response.json();
      if (!response.ok || !data.publicKey) {
        throw new Error("Start the updated Go backend again");
      }
      setTransportPublicKey(data.publicKey);
      setSecurityKeyReady(true);
      return data.publicKey;
    } catch {
      setSecurityKeyReady(false);
      throw new Error("Security key not available. Restart the Go backend server.");
    }
  }

  React.useEffect(() => {
    if (token) {
      loadPasswords();
    }
  }, [token]);

  if (!token) {
    return (
      <main className="auth-page">
        <section className="auth-shell">
          <div className="brand-panel">
            <div className="brand-mark">
              <ShieldCheck size={34} />
            </div>
            <h1>Cipher Safe</h1>
            <p>Private password storage connected to your Go API.</p>
          </div>

          <div className="auth-panel">
            <div className="tabs" aria-label="Authentication options">
              <button className={mode === "login" ? "active" : ""} onClick={() => setMode("login")}>
                Login
              </button>
              <button className={mode === "register" ? "active" : ""} onClick={() => setMode("register")}>
                Register
              </button>
              <button className={mode === "otp" ? "active" : ""} onClick={() => setMode("otp")}>
                OTP
              </button>
            </div>

            {mode === "login" && (
              <LoginForm
                loading={loading}
                setLoading={setLoading}
                setMessage={setMessage}
                setEmailForOtp={setEmailForOtp}
                setMode={setMode}
                apiRequest={apiRequest}
                encryptForServer={encryptForServer}
                securityKeyReady={securityKeyReady}
              />
            )}

            {mode === "register" && (
              <RegisterForm
                loading={loading}
                setLoading={setLoading}
                setMessage={setMessage}
                setEmailForOtp={setEmailForOtp}
                setMode={setMode}
                apiRequest={apiRequest}
                encryptForServer={encryptForServer}
                securityKeyReady={securityKeyReady}
              />
            )}

            {mode === "otp" && (
              <OtpForm
                loading={loading}
                setLoading={setLoading}
                setMessage={setMessage}
                emailForOtp={emailForOtp}
                setEmailForOtp={setEmailForOtp}
                saveToken={saveToken}
                apiRequest={apiRequest}
              />
            )}

            {message && <p className="message">{message}</p>}
          </div>
        </section>
      </main>
    );
  }

  return (
    <main className="app-page">
      <header className="topbar">
        <div>
          <p className="eyebrow">Password vault</p>
          <h1>Saved Passwords</h1>
        </div>
        <div className="topbar-actions">
          <button className="icon-button" onClick={loadPasswords} disabled={loading} title="Refresh passwords">
            <RefreshCw size={18} />
          </button>
          <button className="button ghost" onClick={logout}>
            <LogOut size={18} />
            Logout
          </button>
        </div>
      </header>

      <section className="workspace">
        <PasswordForm
          loading={loading}
          setLoading={setLoading}
          setMessage={setMessage}
          apiRequest={apiRequest}
          loadPasswords={loadPasswords}
          encryptForServer={encryptForServer}
          securityKeyReady={securityKeyReady}
        />

        <PasswordList
          passwords={passwords}
          loading={loading}
          setLoading={setLoading}
          setMessage={setMessage}
          apiRequest={apiRequest}
          loadPasswords={loadPasswords}
          encryptForServer={encryptForServer}
          securityKeyReady={securityKeyReady}
        />
      </section>

      {message && <p className="toast">{message}</p>}
    </main>
  );
}

function LoginForm({ loading, setLoading, setMessage, setEmailForOtp, setMode, apiRequest, encryptForServer, securityKeyReady }) {
  const [form, setForm] = React.useState({ email: "", password: "" });

  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      const data = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
          email: form.email,
          password: await encryptForServer(form.password),
        }),
      });
      setEmailForOtp(form.email);
      setMode("otp");
      setMessage(data.message || "OTP sent to email");
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="form" onSubmit={submit}>
      <Input icon={<Mail size={18} />} label="Email" type="email" value={form.email} onChange={(email) => setForm({ ...form, email })} />
      <Input icon={<Lock size={18} />} label="Password" type="password" value={form.password} onChange={(password) => setForm({ ...form, password })} />
      <button className="button primary" disabled={loading || !securityKeyReady}>
        <KeyRound size={18} />
        {securityKeyReady ? "Send OTP" : "Waiting For Backend"}
      </button>
    </form>
  );
}

function RegisterForm({ loading, setLoading, setMessage, setEmailForOtp, setMode, apiRequest, encryptForServer, securityKeyReady }) {
  const [form, setForm] = React.useState({ name: "", email: "", password: "" });

  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      const data = await apiRequest("/api/auth/register", {
        method: "POST",
        body: JSON.stringify({
          name: form.name,
          email: form.email,
          password: await encryptForServer(form.password),
        }),
      });
      setEmailForOtp(form.email);
      setMode("otp");
      setMessage(data.message || "OTP sent to email");
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="form" onSubmit={submit}>
      <Input icon={<User size={18} />} label="Name" value={form.name} onChange={(name) => setForm({ ...form, name })} />
      <Input icon={<Mail size={18} />} label="Email" type="email" value={form.email} onChange={(email) => setForm({ ...form, email })} />
      <Input icon={<Lock size={18} />} label="Password" type="password" value={form.password} onChange={(password) => setForm({ ...form, password })} />
      <button className="button primary" disabled={loading || !securityKeyReady}>
        <ShieldCheck size={18} />
        {securityKeyReady ? "Create Account" : "Waiting For Backend"}
      </button>
    </form>
  );
}

function OtpForm({ loading, setLoading, setMessage, emailForOtp, setEmailForOtp, saveToken, apiRequest }) {
  const [otp, setOtp] = React.useState("");

  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      const data = await apiRequest("/api/auth/verify-otp", {
        method: "POST",
        body: JSON.stringify({ email: emailForOtp, otp }),
      });
      saveToken(data.token);
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <form className="form" onSubmit={submit}>
      <Input icon={<Mail size={18} />} label="Email" type="email" value={emailForOtp} onChange={setEmailForOtp} />
      <Input icon={<KeyRound size={18} />} label="OTP" value={otp} onChange={setOtp} />
      <button className="button primary" disabled={loading}>
        <ShieldCheck size={18} />
        Verify OTP
      </button>
    </form>
  );
}

function PasswordForm({ loading, setLoading, setMessage, apiRequest, loadPasswords, encryptForServer, securityKeyReady }) {
  const [form, setForm] = React.useState({ website: "", username: "", password: "" });

  async function submit(event) {
    event.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      await apiRequest("/api/passwords", {
        method: "POST",
        body: JSON.stringify({
          website: form.website,
          username: form.username,
          password: await encryptForServer(form.password),
        }),
      });
      setForm({ website: "", username: "", password: "" });
      setMessage("Password added successfully");
      await loadPasswords();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel add-panel">
      <div className="panel-heading">
        <Plus size={20} />
        <h2>Add Password</h2>
      </div>
      <form className="form" onSubmit={submit}>
        <Input icon={<Globe size={18} />} label="Website" value={form.website} onChange={(website) => setForm({ ...form, website })} />
        <Input icon={<User size={18} />} label="Username" value={form.username} onChange={(username) => setForm({ ...form, username })} />
        <Input icon={<Lock size={18} />} label="Password" type="password" value={form.password} onChange={(password) => setForm({ ...form, password })} />
        <button className="button primary" disabled={loading || !securityKeyReady}>
          <Plus size={18} />
          {securityKeyReady ? "Add Password" : "Waiting For Backend"}
        </button>
      </form>
    </section>
  );
}

function PasswordList({ passwords, loading, setLoading, setMessage, apiRequest, loadPasswords, encryptForServer, securityKeyReady }) {
  const [visibleIds, setVisibleIds] = React.useState({});
  const [revealedPasswords, setRevealedPasswords] = React.useState({});
  const [editingId, setEditingId] = React.useState("");
  const [editForm, setEditForm] = React.useState({ website: "", username: "", password: "" });
  const [searchText, setSearchText] = React.useState("");

  const filteredPasswords = passwords.filter((item) => {
    const searchValue = searchText.trim().toLowerCase();
    if (searchValue === "") {
      return true;
    }

    return (
      item.website.toLowerCase().includes(searchValue) ||
      item.username.toLowerCase().includes(searchValue)
    );
  });

  async function removePassword(id) {
    setLoading(true);
    setMessage("");
    try {
      await apiRequest(`/api/passwords/${id}`, { method: "DELETE" });
      setMessage("Password deleted successfully");
      await loadPasswords();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  function startEdit(item) {
    setEditingId(item._id);
    setEditForm({
      website: item.website,
      username: item.username,
      password: "",
    });
    setVisibleIds({ ...visibleIds, [item._id]: false });
  }

  function cancelEdit() {
    setEditingId("");
    setEditForm({ website: "", username: "", password: "" });
  }

  async function updatePassword(event, id) {
    event.preventDefault();
    setLoading(true);
    setMessage("");
    try {
      await apiRequest(`/api/passwords/${id}`, {
        method: "PUT",
        body: JSON.stringify({
          website: editForm.website,
          username: editForm.username,
          password: await encryptForServer(editForm.password),
        }),
      });
      setRevealedPasswords({ ...revealedPasswords, [id]: "" });
      cancelEdit();
      setMessage("Password updated successfully");
      await loadPasswords();
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  async function revealPassword(id) {
    if (visibleIds[id]) {
      setVisibleIds({ ...visibleIds, [id]: false });
      return;
    }

    if (revealedPasswords[id]) {
      setVisibleIds({ ...visibleIds, [id]: true });
      return;
    }

    setLoading(true);
    setMessage("");
    try {
      const keyPair = await createBrowserKeyPair();
      const publicKey = await exportPublicKey(keyPair.publicKey);
      const data = await apiRequest(`/api/passwords/${id}/reveal`, {
        method: "POST",
        body: JSON.stringify({ publicKey }),
      });
      const plainPassword = await decryptWithPrivateKey(keyPair.privateKey, data.password);
      setRevealedPasswords({ ...revealedPasswords, [id]: plainPassword });
      setVisibleIds({ ...visibleIds, [id]: true });
    } catch (error) {
      setMessage(error.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="panel list-panel">
      <div className="panel-heading">
        <KeyRound size={20} />
        <h2>Your Vault</h2>
        <span>{filteredPasswords.length}</span>
      </div>

      <div className="search-box">
        <Search size={18} />
        <input
          type="search"
          value={searchText}
          onChange={(event) => setSearchText(event.target.value)}
          placeholder="Search website or username"
        />
      </div>

      {passwords.length === 0 ? (
        <div className="empty-state">
          <Lock size={30} />
          <p>No passwords saved yet.</p>
        </div>
      ) : filteredPasswords.length === 0 ? (
        <div className="empty-state">
          <Search size={30} />
          <p>No matching password found.</p>
        </div>
      ) : (
        <div className="password-grid">
          {filteredPasswords.map((item) => {
            const id = item._id;
            const isVisible = Boolean(visibleIds[id]);
            const isEditing = editingId === id;

            if (isEditing) {
              return (
                <article className="password-card editing-card" key={id}>
                  <form className="edit-form" onSubmit={(event) => updatePassword(event, id)}>
                    <Input icon={<Globe size={18} />} label="Website" value={editForm.website} onChange={(website) => setEditForm({ ...editForm, website })} />
                    <Input icon={<User size={18} />} label="Username" value={editForm.username} onChange={(username) => setEditForm({ ...editForm, username })} />
                    <Input icon={<Lock size={18} />} label="New Password" type="password" value={editForm.password} onChange={(password) => setEditForm({ ...editForm, password })} />
                    <div className="edit-actions">
                      <button className="button primary" disabled={loading || !securityKeyReady}>
                        <Save size={17} />
                        Save
                      </button>
                      <button className="button ghost" type="button" onClick={cancelEdit}>
                        <X size={17} />
                        Cancel
                      </button>
                    </div>
                  </form>
                </article>
              );
            }

            return (
              <article className="password-card" key={id}>
                <div>
                  <h3>{item.website}</h3>
                  <p>{item.username}</p>
                </div>
                <div className="secret-row">
                  <code>{isVisible ? revealedPasswords[id] : "************"}</code>
                  <button
                    className="icon-button"
                    onClick={() => revealPassword(id)}
                    title={isVisible ? "Hide password" : "Show password"}
                  >
                    {isVisible ? <EyeOff size={17} /> : <Eye size={17} />}
                  </button>
                  <button className="icon-button" onClick={() => startEdit(item)} disabled={loading} title="Edit password">
                    <Pencil size={17} />
                  </button>
                  <button className="icon-button danger" onClick={() => removePassword(id)} disabled={loading} title="Delete password">
                    <Trash2 size={17} />
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function Input({ icon, label, value, onChange, type = "text" }) {
  return (
    <label className="field">
      <span>{label}</span>
      <div className="input-wrap">
        {icon}
        <input required type={type} value={value} onChange={(event) => onChange(event.target.value)} placeholder={label} />
      </div>
    </label>
  );
}

async function encryptWithPublicKey(publicKeyPEM, value) {
  const publicKey = await importPublicKey(publicKeyPEM);
  const cipherBuffer = await window.crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    publicKey,
    new TextEncoder().encode(value),
  );
  return arrayBufferToBase64(cipherBuffer);
}

async function importPublicKey(publicKeyPEM) {
  const cleanKey = publicKeyPEM
    .replace("-----BEGIN PUBLIC KEY-----", "")
    .replace("-----END PUBLIC KEY-----", "")
    .replace(/\s/g, "");

  return window.crypto.subtle.importKey(
    "spki",
    base64ToArrayBuffer(cleanKey),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"],
  );
}

async function createBrowserKeyPair() {
  return window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"],
  );
}

async function exportPublicKey(publicKey) {
  const keyBuffer = await window.crypto.subtle.exportKey("spki", publicKey);
  const base64Key = arrayBufferToBase64(keyBuffer);
  return `-----BEGIN PUBLIC KEY-----\n${base64Key.match(/.{1,64}/g).join("\n")}\n-----END PUBLIC KEY-----`;
}

async function decryptWithPrivateKey(privateKey, encodedCipher) {
  const plainBuffer = await window.crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    base64ToArrayBuffer(encodedCipher),
  );
  return new TextDecoder().decode(plainBuffer);
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return window.btoa(binary);
}

function base64ToArrayBuffer(value) {
  const binary = window.atob(value);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

createRoot(document.getElementById("root")).render(<App />);
