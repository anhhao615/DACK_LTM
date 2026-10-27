/**
 * Unified API Client for Remote File Access System
 */
const API = {
  getToken() {
    return localStorage.getItem("jwt_token");
  },

  setToken(token) {
    if (token) {
      localStorage.setItem("jwt_token", token);
    } else {
      localStorage.removeItem("jwt_token");
    }
  },

  getUser() {
    const raw = localStorage.getItem("current_user");
    return raw ? JSON.parse(raw) : null;
  },

  setUser(user) {
    if (user) {
      localStorage.setItem("current_user", JSON.stringify(user));
    } else {
      localStorage.removeItem("current_user");
    }
  },

  async request(endpoint, options = {}) {
    const headers = options.headers || {};
    const token = this.getToken();

    if (token && !headers["Authorization"]) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    if (!(options.body instanceof FormData) && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }

    options.headers = headers;

    try {
      const response = await fetch(endpoint, options);
      const data = await response.json().catch(() => ({}));

      if (!response.ok) {
        // Construct comprehensive error object
        const error = new Error(data.message || `Request failed with code ${response.status}`);
        error.status = response.status;
        error.data = data;
        throw error;
      }

      return data;
    } catch (err) {
      if (err.status === 401 && !endpoint.includes("/login")) {
        // Token expired or invalid
        this.setToken(null);
        this.setUser(null);
        window.dispatchEvent(new CustomEvent("auth:unauthorized"));
      }
      throw err;
    }
  },

  // Auth Endpoints
  async login(username, password) {
    const res = await this.request("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password })
    });
    this.setToken(res.access_token);
    this.setUser(res.user);
    return res;
  },

  async logout() {
    try {
      await this.request("/api/auth/logout", { method: "POST" });
    } catch (e) {
      console.warn("Logout notification failed:", e);
    } finally {
      this.setToken(null);
      this.setUser(null);
    }
  },

  async getMe() {
    return this.request("/api/auth/me");
  },

  // File Operations
  async listFiles(path = "/") {
    const q = encodeURIComponent(path);
    return this.request(`/api/files/list?path=${q}`);
  },

  async getFileContent(path) {
    const q = encodeURIComponent(path);
    return this.request(`/api/files/content?path=${q}`);
  },

  async writeFile(path, filename, content) {
    return this.request("/api/files/write", {
      method: "POST",
      body: JSON.stringify({ path, filename, content })
    });
  },

  async uploadFile(file, path) {
    const formData = new FormData();
    formData.append("file", file);
    formData.append("path", path);

    return this.request("/api/files/upload", {
      method: "POST",
      body: formData
    });
  },

  async mkdir(path, dir_name) {
    return this.request("/api/files/mkdir", {
      method: "POST",
      body: JSON.stringify({ path, dir_name })
    });
  },

  async deleteFile(path) {
    return this.request("/api/files/delete", {
      method: "DELETE",
      body: JSON.stringify({ path })
    });
  },

  getDownloadUrl(path) {
    return `/api/files/download?path=${encodeURIComponent(path)}`;
  },

  async downloadFile(path, filename) {
    const token = this.getToken();
    const headers = {};
    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    const response = await fetch(`/api/files/download?path=${encodeURIComponent(path)}`, {
      headers: headers
    });

    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      throw new Error(data.message || `Lỗi tải tệp tin (Mã lỗi ${response.status})`);
    }

    const blob = await response.blob();
    const blobUrl = window.URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = blobUrl;
    link.download = filename || path.split("/").filter(Boolean).pop() || "download";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => window.URL.revokeObjectURL(blobUrl), 1000);
  },

  async getSystemStatus() {
    return this.request("/api/system/status");
  },

  // SOC Endpoints
  async getAuditLogs(status = "ALL", limit = 100) {
    return this.request(`/api/soc/logs?status=${encodeURIComponent(status)}&limit=${limit}`);
  },

  async getSOCStats() {
    return this.request("/api/soc/stats");
  },

  async getFirewallRules() {
    return this.request("/api/soc/firewall/rules");
  },

  async addFirewallRule(rule) {
    return this.request("/api/soc/firewall/rules", {
      method: "POST",
      body: JSON.stringify(rule)
    });
  },

  async deleteFirewallRule(id) {
    return this.request(`/api/soc/firewall/rules/${id}`, {
      method: "DELETE"
    });
  },

  async getFirewallSettings() {
    return this.request("/api/soc/firewall/settings");
  },

  async updateFirewallSettings(settings) {
    return this.request("/api/soc/firewall/settings", {
      method: "POST",
      body: JSON.stringify(settings)
    });
  },

  async getQuarantineRecords() {
    return this.request("/api/soc/antivirus/quarantine");
  },

  async deleteQuarantineRecord(id) {
    return this.request(`/api/soc/antivirus/quarantine/${id}`, {
      method: "DELETE"
    });
  },

  async getACLRules() {
    return this.request("/api/soc/acl/rules");
  },

  async setACLRule(rule) {
    return this.request("/api/soc/acl/rules", {
      method: "POST",
      body: JSON.stringify(rule)
    });
  },

  async deleteACLRule(id) {
    return this.request(`/api/soc/acl/rules/${id}`, {
      method: "DELETE"
    });
  },

  async getUsers() {
    return this.request("/api/soc/users");
  },

  async registerUser(data) {
    return this.request("/api/auth/register", {
      method: "POST",
      body: JSON.stringify(data)
    });
  },

  async forgotPassword(data) {
    return this.request("/api/auth/forgot-password", {
      method: "POST",
      body: JSON.stringify(data)
    });
  },

  async requestPasswordReset(username, reason) {
    return this.request("/api/auth/forgot-password/request", {
      method: "POST",
      body: JSON.stringify({ username, reason })
    });
  },

  async confirmPasswordReset(username, code, newPassword) {
    return this.request("/api/auth/forgot-password/confirm", {
      method: "POST",
      body: JSON.stringify({ username, code, new_password: newPassword })
    });
  },

  async getPasswordResetRequests() {
    return this.request("/api/soc/password-resets");
  },

  async approvePasswordReset(username) {
    return this.request("/api/soc/password-resets/approve", {
      method: "POST",
      body: JSON.stringify({ username })
    });
  },

  async rejectPasswordReset(username) {
    return this.request("/api/soc/password-resets/reject", {
      method: "POST",
      body: JSON.stringify({ username })
    });
  },

  async approveUser(username) {
    return this.request("/api/soc/users/approve", {
      method: "POST",
      body: JSON.stringify({ username })
    });
  },

  async unlockUser(username) {
    return this.request("/api/soc/users/unlock", {
      method: "POST",
      body: JSON.stringify({ username })
    });
  },

  async lockUser(username, reason) {
    return this.request("/api/soc/users/lock", {
      method: "POST",
      body: JSON.stringify({ username, reason })
    });
  },

  async resetUserPassword(username, newPassword) {
    return this.request("/api/soc/users/reset-password", {
      method: "POST",
      body: JSON.stringify({ username, new_password: newPassword })
    });
  },

  async deleteUser(username) {
    return this.request("/api/soc/users/delete", {
      method: "POST",
      body: JSON.stringify({ username })
    });
  },

  async getSystemStatus() {
    return this.request("/api/system/status");
  }
};
