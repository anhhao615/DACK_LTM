/**
 * SecureCloud Drive - Controller Ứng Dụng Lưu Trữ Tệp Tin Doanh Nghiệp
 * Phong cách Trắng - Xanh Dương - Chữ Đen
 */
const App = {
  currentPath: "/",
  currentEditFile: null,
  currentPreviewFile: null,
  rawItems: [],
  rawSocUsers: [],
  socUserStatusFilter: "ALL",
  socUserSearchTerm: "",
  currentBadge: "Unknown",
  viewMode: "grid", // 'grid' hoặc 'list'
  logRefreshInterval: null,
  lanUrl: `http://${window.location.hostname || "localhost"}:8080/`,
  publicUrl: "",

  init() {
    // 1. Phục hồi chế độ xem ưa thích (Lưới hoặc Danh sách)
    const savedView = localStorage.getItem("file_view_mode");
    if (savedView === "list" || savedView === "grid") {
      this.viewMode = savedView;
    }
    this.updateViewModeButtons();

    // 2. Kiểm tra trạng thái máy chủ & lấy địa chỉ mạng LAN
    this.fetchSystemInfo();

    // 3. Kiểm tra trạng thái đăng nhập
    const user = API.getUser();
    const token = API.getToken();

    if (token && user) {
      this.showAppView();
    } else {
      this.showLoginView();
    }

    // 4. Lắng nghe sự kiện hết hạn token
    window.addEventListener("auth:unauthorized", () => {
      this.showToast("Phiên làm việc đã hết hạn hoặc không hợp lệ. Vui lòng đăng nhập lại.", "warning");
      this.showLoginView();
    });

    // 5. Khởi tạo tính năng kéo thả tệp tin (Drag & Drop)
    this.initDragAndDrop();

    // 6. Phím tắt tìm kiếm (nhấn / để focus ô tìm kiếm)
    window.addEventListener("keydown", (e) => {
      if (e.key === "/" && document.activeElement.tagName !== "INPUT" && document.activeElement.tagName !== "TEXTAREA") {
        e.preventDefault();
        const searchInput = document.getElementById("global-file-search");
        if (searchInput) searchInput.focus();
      }
    });

    // 7. Tự động đồng bộ nhiều máy (Multi-device Realtime Sync mỗi 8s)
    setInterval(() => {
      if (this.currentPath && !document.hidden && API.getToken()) {
        this.syncFilesSilently();
      }
    }, 8000);

    // 8. Tự động làm mới khi người dùng quay lại cửa sổ trình duyệt
    window.addEventListener("focus", () => {
      if (API.getToken() && this.currentPath) {
        this.syncFilesSilently();
        this.fetchSystemInfo();
      }
    });
  },

  // =========================================================================
  // AUTHENTICATION & VIEW SWITCHING
  // =========================================================================
  showLoginView() {
    const viewLogin = document.getElementById("view-login");
    const viewApp = document.getElementById("view-app");
    if (viewLogin) viewLogin.classList.remove("hidden");
    if (viewApp) viewApp.classList.add("hidden");

    // Xóa form và lỗi
    const uInput = document.getElementById("login-username");
    const pInput = document.getElementById("login-password");
    const errBox = document.getElementById("login-error-msg");
    if (uInput) uInput.value = "";
    if (pInput) pInput.value = "";
    if (errBox) errBox.classList.add("hidden");

    if (this.logRefreshInterval) {
      clearInterval(this.logRefreshInterval);
      this.logRefreshInterval = null;
    }
  },

  showAppView() {
    const viewLogin = document.getElementById("view-login");
    const viewApp = document.getElementById("view-app");
    if (viewLogin) viewLogin.classList.add("hidden");
    if (viewApp) viewApp.classList.remove("hidden");

    this.updateUserContextUI();
    this.loadFiles(this.currentPath);
    this.loadSOCStats();
    this.loadQuarantineCount();
    this.toggleAutoRefreshLogs(true);
  },

  updateUserContextUI() {
    const user = API.getUser();
    if (!user) return;

    const navUsername = document.getElementById("nav-username");
    const navFullname = document.getElementById("nav-fullname");
    const navRole = document.getElementById("nav-role");
    const userAvatar = document.getElementById("user-avatar");
    const adminElements = document.querySelectorAll(".admin-only");

    if (navUsername) navUsername.textContent = `@${user.username}`;
    if (navFullname) navFullname.textContent = user.full_name || user.username;

    // Avatar initials (2 chữ cái)
    if (userAvatar) {
      const initials = (user.full_name || user.username)
        .split(" ")
        .filter(Boolean)
        .map(w => w[0].toUpperCase())
        .slice(0, 2)
        .join("");
      userAvatar.textContent = initials || "U";

      if (user.role === "ADMIN") {
        userAvatar.className = "w-7 h-7 sm:w-8 sm:h-8 rounded-full bg-purple-100 border border-purple-300 flex items-center justify-center font-bold text-xs text-purple-700 shadow-sm";
      } else if (user.role === "USER") {
        userAvatar.className = "w-7 h-7 sm:w-8 sm:h-8 rounded-full bg-blue-100 border border-blue-300 flex items-center justify-center font-bold text-xs text-blue-700 shadow-sm";
      } else {
        userAvatar.className = "w-7 h-7 sm:w-8 sm:h-8 rounded-full bg-amber-100 border border-amber-300 flex items-center justify-center font-bold text-xs text-amber-700 shadow-sm";
      }
    }

    if (navRole) {
      navRole.textContent = user.role;
      navRole.className = `text-[10px] px-1.5 py-0.2 rounded font-bold ${
        user.role === "ADMIN" ? "bg-purple-50 text-purple-700 border border-purple-200" :
        user.role === "USER" ? "bg-blue-50 text-blue-700 border border-blue-200" :
        "bg-slate-100 text-slate-700 border border-slate-200"
      }`;
    }

    // Hiển thị hoặc ẩn các chức năng quản trị chỉ dành cho ADMIN
    adminElements.forEach(el => {
      if (user.role === "ADMIN") {
        el.classList.remove("hidden");
      } else {
        el.classList.add("hidden");
      }
    });
  },

  async handleLoginForm(e) {
    if (e) e.preventDefault();
    const usernameInput = document.getElementById("login-username");
    const passwordInput = document.getElementById("login-password");
    const errBox = document.getElementById("login-error-msg");
    const errText = document.getElementById("login-error-text");
    const errTitle = document.getElementById("login-error-title");
    const errIcon = document.getElementById("login-error-icon");
    const btnSubmit = document.getElementById("btn-login-submit");

    const username = usernameInput ? usernameInput.value.trim() : "";
    const password = passwordInput ? passwordInput.value : "";

    if (!username || !password) {
      if (errBox && errText) {
        if (errTitle) errTitle.textContent = "Thiếu thông tin đăng nhập";
        errText.textContent = "Vui lòng nhập đầy đủ tên đăng nhập và mật khẩu.";
        errBox.className = "p-3.5 rounded-xl bg-amber-50 border border-amber-300 text-xs text-amber-800 flex items-start space-x-2.5 shadow-sm";
        if (errIcon) errIcon.className = "fa-solid fa-circle-exclamation text-amber-600 mt-0.5 text-sm flex-shrink-0";
        errBox.classList.remove("hidden");
      }
      return;
    }

    if (errBox) errBox.classList.add("hidden");
    if (btnSubmit) {
      btnSubmit.disabled = true;
      btnSubmit.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-2"></i>Đang xác thực bảo mật...`;
    }

    try {
      const res = await API.login(username, password);
      this.showToast(`Chào mừng ${res.user.full_name || res.user.username} đã đăng nhập!`, "success");
      this.showAppView();
    } catch (err) {
      const errData = err.data || {};
      const status = errData.status;

      if (errBox && errText) {
        if (status === "LOCKED") {
          // Tài khoản bị khóa do sai 3 lần
          errBox.className = "p-3.5 rounded-xl bg-rose-50 border border-rose-300 text-xs text-rose-800 flex items-start space-x-2.5 shadow-sm";
          if (errIcon) errIcon.className = "fa-solid fa-lock text-rose-600 mt-0.5 text-sm flex-shrink-0";
          if (errTitle) errTitle.textContent = "TÀI KHOẢN ĐÃ BỊ KHÓA BẢO MẬT";
          errText.innerHTML = `
            <div>${err.message || "Tài khoản của bạn đã bị KHÓA do nhập sai mật khẩu 3 lần liên tiếp."}</div>
            <div class="mt-2 text-[11px] text-rose-700 font-semibold">Chỉ có <strong>Quản trị viên (Admin)</strong> mới có quyền mở khóa tài khoản, hoặc bạn có thể tự khôi phục:</div>
            <button type="button" onclick="App.openForgotPasswordModal('${username}')" class="mt-2.5 inline-flex items-center space-x-1.5 px-3 py-1.5 bg-white border border-rose-300 rounded-lg text-rose-700 font-bold hover:bg-rose-100 transition shadow-sm">
              <i class="fa-solid fa-key"></i>
              <span>Khôi Phục Mật Khẩu & Mở Khóa Ngay</span>
            </button>
          `;
        } else if (status === "PENDING") {
          // Tài khoản đang chờ duyệt
          errBox.className = "p-3.5 rounded-xl bg-amber-50 border border-amber-300 text-xs text-amber-900 flex items-start space-x-2.5 shadow-sm";
          if (errIcon) errIcon.className = "fa-solid fa-hourglass-half text-amber-600 mt-0.5 text-sm flex-shrink-0 animate-spin";
          if (errTitle) errTitle.textContent = "TÀI KHOẢN ĐANG CHỜ ADMIN PHÊ DUYỆT";
          errText.innerHTML = `
            <div>${err.message || "Tài khoản mới đăng ký đang ở trạng thái chờ duyệt."}</div>
            <div class="mt-1.5 text-[11px] text-amber-800 font-medium">Vui lòng thông báo cho <strong>Quản trị viên (Admin: @admin)</strong> để duyệt tài khoản của bạn vào hệ thống.</div>
          `;
        } else if (errData.remaining_attempts !== undefined) {
          // Sai mật khẩu - Còn lượt thử
          const rem = errData.remaining_attempts;
          errBox.className = "p-3.5 rounded-xl bg-amber-50 border border-amber-300 text-xs text-amber-900 flex items-start space-x-2.5 shadow-sm";
          if (errIcon) errIcon.className = "fa-solid fa-triangle-exclamation text-amber-600 mt-0.5 text-sm flex-shrink-0";
          if (errTitle) errTitle.textContent = `SAI MẬT KHẨU (CÒN ${rem}/3 LẦN THỬ)`;
          errText.innerHTML = `
            <div>${err.message || "Mật khẩu không chính xác."}</div>
            <div class="mt-1 text-[11px] text-rose-600 font-bold">Lưu ý: Nếu nhập sai tiếp quá 3 lần, tài khoản sẽ tự động bị KHÓA hoàn toàn!</div>
          `;
        } else {
          // Lỗi thông thường
          errBox.className = "p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-800 flex items-start space-x-2.5";
          if (errIcon) errIcon.className = "fa-solid fa-circle-exclamation text-rose-600 mt-0.5 text-sm flex-shrink-0";
          if (errTitle) errTitle.textContent = "ĐĂNG NHẬP THẤT BÀI";
          errText.textContent = err.message || "Tên tài khoản hoặc mật khẩu không chính xác.";
        }
        errBox.classList.remove("hidden");
      }
      this.showToast(err.message || "Đăng nhập thất bại", "error");
    } finally {
      if (btnSubmit) {
        btnSubmit.disabled = false;
        btnSubmit.innerHTML = `<span>Đăng Nhập Vào Hệ Thống</span><i class="fa-solid fa-arrow-right ml-2"></i>`;
      }
    }
  },

  // =========================================================================
  // REGISTER & FORGOT PASSWORD WORKFLOWS
  // =========================================================================
  openRegisterModal() {
    const uInput = document.getElementById("reg-username");
    const fnInput = document.getElementById("reg-fullname");
    const pInput = document.getElementById("reg-password");
    const cpInput = document.getElementById("reg-confirm-password");
    const rInput = document.getElementById("reg-reason");
    const errBox = document.getElementById("reg-error-msg");

    if (uInput) uInput.value = "";
    if (fnInput) fnInput.value = "";
    if (pInput) pInput.value = "";
    if (cpInput) cpInput.value = "";
    if (rInput) rInput.value = "";
    if (errBox) {
      errBox.textContent = "";
      errBox.classList.add("hidden");
    }

    this.showModal("modal-register");
  },

  async handleRegisterForm(e) {
    if (e) e.preventDefault();
    const username = (document.getElementById("reg-username")?.value || "").trim().toLowerCase();
    const fullName = (document.getElementById("reg-fullname")?.value || "").trim();
    const password = document.getElementById("reg-password")?.value || "";
    const confirmPassword = document.getElementById("reg-confirm-password")?.value || "";
    const roleRadio = document.querySelector('input[name="reg-role"]:checked');
    const role = roleRadio ? roleRadio.value : "USER";
    const reason = (document.getElementById("reg-reason")?.value || "").trim();
    const errBox = document.getElementById("reg-error-msg");
    const btnSubmit = document.getElementById("btn-reg-submit");

    if (!username || !fullName || !password) {
      if (errBox) {
        errBox.textContent = "Vui lòng điền đầy đủ các thông tin bắt buộc (*).";
        errBox.classList.remove("hidden");
      }
      return;
    }

    if (password !== confirmPassword) {
      if (errBox) {
        errBox.textContent = "Mật khẩu và xác nhận mật khẩu không khớp nhau.";
        errBox.classList.remove("hidden");
      }
      return;
    }

    if (password.length < 4) {
      if (errBox) {
        errBox.textContent = "Mật khẩu phải có độ dài tối thiểu 4 ký tự.";
        errBox.classList.remove("hidden");
      }
      return;
    }

    if (errBox) errBox.classList.add("hidden");
    if (btnSubmit) {
      btnSubmit.disabled = true;
      btnSubmit.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-2"></i>Đang gửi yêu cầu...`;
    }

    try {
      const res = await API.registerUser({
        username,
        full_name: fullName,
        role,
        password,
        reason
      });

      this.hideModal("modal-register");
      this.showToast("Đăng ký thành công! Tài khoản đang chờ Admin phê duyệt.", "success");

      // Cập nhật sẵn username vào khung đăng nhập và hiển thị thông báo chờ duyệt
      const loginUInput = document.getElementById("login-username");
      const loginPInput = document.getElementById("login-password");
      if (loginUInput) loginUInput.value = username;
      if (loginPInput) loginPInput.value = "";

      const loginErrBox = document.getElementById("login-error-msg");
      const loginErrTitle = document.getElementById("login-error-title");
      const loginErrText = document.getElementById("login-error-text");
      const loginErrIcon = document.getElementById("login-error-icon");

      if (loginErrBox && loginErrText) {
        loginErrBox.className = "p-3.5 rounded-xl bg-amber-50 border border-amber-300 text-xs text-amber-900 flex items-start space-x-2.5 shadow-sm";
        if (loginErrIcon) loginErrIcon.className = "fa-solid fa-hourglass-half text-amber-600 mt-0.5 text-sm flex-shrink-0 animate-spin";
        if (loginErrTitle) loginErrTitle.textContent = "ĐĂNG KÝ THÀNH CÔNG - CHỜ ADMIN DUYỆT";
        loginErrText.innerHTML = `
          <div>Tài khoản <strong>@${username}</strong> (${role}) đã được ghi nhận.</div>
          <div class="mt-1 text-[11px] text-amber-800">Vui lòng liên hệ <strong>Quản trị viên (Admin)</strong> để được kích hoạt tài khoản trước khi đăng nhập.</div>
        `;
        loginErrBox.classList.remove("hidden");
      }

    } catch (err) {
      if (errBox) {
        errBox.textContent = err.message || "Đăng ký thất bại. Vui lòng thử lại.";
        errBox.classList.remove("hidden");
      }
      this.showToast(err.message || "Lỗi đăng ký tài khoản", "error");
    } finally {
      if (btnSubmit) {
        btnSubmit.disabled = false;
        btnSubmit.innerHTML = `<i class="fa-solid fa-paper-plane mr-2"></i><span>Gửi Yêu Cầu Đăng Ký</span>`;
      }
    }
  },

  openForgotPasswordModal(prefillUsername = "") {
    const defaultUser = prefillUsername || (document.getElementById("login-username")?.value || "").trim();
    
    // Clear and reset Step 1 fields
    const u1 = document.getElementById("forgot-step1-username");
    const r1 = document.getElementById("forgot-step1-reason");
    const msg1 = document.getElementById("forgot-step1-msg");
    if (u1) u1.value = defaultUser;
    if (r1) r1.value = "";
    if (msg1) {
      msg1.textContent = "";
      msg1.className = "hidden p-3 rounded-xl text-xs font-medium";
    }

    // Clear and reset Step 2 fields (NO pre-filled code!)
    const u2 = document.getElementById("forgot-step2-username");
    const c2 = document.getElementById("forgot-step2-code");
    const p2 = document.getElementById("forgot-step2-password");
    const cp2 = document.getElementById("forgot-step2-confirm");
    const msg2 = document.getElementById("forgot-step2-msg");
    if (u2) u2.value = defaultUser;
    if (c2) c2.value = ""; // Empty blank, no prefill!
    if (p2) p2.value = "";
    if (cp2) cp2.value = "";
    if (msg2) {
      msg2.textContent = "";
      msg2.className = "hidden p-3 rounded-xl text-xs font-medium";
    }

    this.switchForgotStep(1);
    this.showModal("modal-forgot-password");
  },

  switchForgotStep(step) {
    const s1 = document.getElementById("forgot-step-1");
    const s2 = document.getElementById("forgot-step-2");
    const btn1 = document.getElementById("tab-btn-forgot-step1");
    const btn2 = document.getElementById("tab-btn-forgot-step2");

    if (step === 1) {
      if (s1) s1.classList.remove("hidden");
      if (s2) s2.classList.add("hidden");
      if (btn1) btn1.className = "py-2 rounded-lg bg-white text-blue-700 shadow-sm transition flex items-center justify-center space-x-1.5";
      if (btn2) btn2.className = "py-2 rounded-lg text-slate-600 hover:text-slate-900 transition flex items-center justify-center space-x-1.5";
    } else {
      if (s1) s1.classList.add("hidden");
      if (s2) s2.classList.remove("hidden");
      if (btn2) btn2.className = "py-2 rounded-lg bg-white text-blue-700 shadow-sm transition flex items-center justify-center space-x-1.5";
      if (btn1) btn1.className = "py-2 rounded-lg text-slate-600 hover:text-slate-900 transition flex items-center justify-center space-x-1.5";

      // Sync username from step 1 to step 2 if step 2 is empty
      const u1Val = (document.getElementById("forgot-step1-username")?.value || "").trim();
      const u2 = document.getElementById("forgot-step2-username");
      if (u1Val && u2 && !u2.value) {
        u2.value = u1Val;
      }
    }
  },

  async handleForgotPasswordRequestForm(e) {
    if (e) e.preventDefault();
    const username = (document.getElementById("forgot-step1-username")?.value || "").trim().toLowerCase();
    const reason = (document.getElementById("forgot-step1-reason")?.value || "").trim();
    const msgEl = document.getElementById("forgot-step1-msg");
    const btn = document.getElementById("btn-forgot-step1-submit");

    if (!username) {
      if (msgEl) {
        msgEl.className = "p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium";
        msgEl.textContent = "Vui lòng nhập tên đăng nhập của bạn.";
        msgEl.classList.remove("hidden");
      }
      return;
    }

    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-2"></i>Đang gửi yêu cầu...`;
    }

    try {
      const res = await API.requestPasswordReset(username, reason);
      if (msgEl) {
        msgEl.className = "p-3.5 rounded-xl bg-emerald-50 border border-emerald-300 text-xs text-emerald-900 font-medium space-y-1";
        msgEl.innerHTML = `
          <div class="font-bold flex items-center space-x-1.5 text-emerald-800">
            <i class="fa-solid fa-circle-check text-emerald-600"></i>
            <span>Đã gửi yêu cầu thành công!</span>
          </div>
          <p>Yêu cầu khôi phục cho tài khoản <strong>@${username}</strong> đang chờ <strong>Quản trị viên (Admin)</strong> phê duyệt.</p>
          <p class="text-[11px] text-emerald-700">Vui lòng liên hệ Admin để nhận <strong>Mã xác thực khôi phục (6 chữ số)</strong> rồi chuyển sang Bước 2 để đặt lại mật khẩu mới.</p>
        `;
        msgEl.classList.remove("hidden");
      }
      this.showToast("Đã gửi yêu cầu đến Admin! Chờ Admin duyệt cấp mã.", "success");

      // Đồng bộ tên tài khoản sang Bước 2
      const u2 = document.getElementById("forgot-step2-username");
      if (u2) u2.value = username;

      // Tự động chuyển sang Bước 2 sau 2.5 giây để người dùng sẵn sàng nhập mã
      setTimeout(() => {
        this.switchForgotStep(2);
      }, 2500);

    } catch (err) {
      if (msgEl) {
        msgEl.className = "p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium";
        msgEl.textContent = err.message || "Gửi yêu cầu thất bại. Vui lòng kiểm tra lại tên tài khoản.";
        msgEl.classList.remove("hidden");
      }
      this.showToast(err.message || "Lỗi gửi yêu cầu khôi phục", "error");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-paper-plane mr-1.5"></i>Gửi Yêu Cầu Cho Admin`;
      }
    }
  },

  async handleForgotPasswordConfirmForm(e) {
    if (e) e.preventDefault();
    const username = (document.getElementById("forgot-step2-username")?.value || "").trim().toLowerCase();
    const code = (document.getElementById("forgot-step2-code")?.value || "").trim();
    const newPassword = document.getElementById("forgot-step2-password")?.value || "";
    const confirmPassword = document.getElementById("forgot-step2-confirm")?.value || "";
    const msgEl = document.getElementById("forgot-step2-msg");
    const btn = document.getElementById("btn-forgot-step2-submit");

    if (!username || !code || !newPassword) {
      if (msgEl) {
        msgEl.className = "p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium";
        msgEl.textContent = "Vui lòng nhập đầy đủ Tên tài khoản, Mã xác thực và Mật khẩu mới.";
        msgEl.classList.remove("hidden");
      }
      return;
    }

    if (newPassword !== confirmPassword) {
      if (msgEl) {
        msgEl.className = "p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium";
        msgEl.textContent = "Mật khẩu mới và xác nhận mật khẩu không khớp nhau.";
        msgEl.classList.remove("hidden");
      }
      return;
    }

    if (newPassword.length < 4) {
      if (msgEl) {
        msgEl.className = "p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium";
        msgEl.textContent = "Mật khẩu mới phải có tối thiểu 4 ký tự.";
        msgEl.classList.remove("hidden");
      }
      return;
    }

    if (msgEl) msgEl.classList.add("hidden");
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-2"></i>Đang xác thực...`;
    }

    try {
      const res = await API.confirmPasswordReset(username, code, newPassword);

      this.hideModal("modal-forgot-password");
      this.showToast("Đặt lại mật khẩu thành công! Tài khoản đã được mở khóa.", "success");

      // Cập nhật thông tin vào màn hình đăng nhập
      const loginUInput = document.getElementById("login-username");
      const loginPInput = document.getElementById("login-password");
      if (loginUInput) loginUInput.value = username;
      if (loginPInput) loginPInput.value = newPassword;

      const loginErrBox = document.getElementById("login-error-msg");
      const loginErrTitle = document.getElementById("login-error-title");
      const loginErrText = document.getElementById("login-error-text");
      const loginErrIcon = document.getElementById("login-error-icon");

      if (loginErrBox && loginErrText) {
        loginErrBox.className = "p-3.5 rounded-xl bg-emerald-50 border border-emerald-300 text-xs text-emerald-900 flex items-start space-x-2.5 shadow-sm";
        if (loginErrIcon) loginErrIcon.className = "fa-solid fa-circle-check text-emerald-600 mt-0.5 text-sm flex-shrink-0";
        if (loginErrTitle) loginErrTitle.textContent = "KHÔI PHỤC MẬT KHẨU THÀNH CÔNG";
        loginErrText.innerHTML = `Tài khoản <strong>@${username}</strong> đã được đặt lại mật khẩu và mở khóa thành công. Nhấn nút <strong>Đăng Nhập</strong> để vào hệ thống.`;
        loginErrBox.classList.remove("hidden");
      }

    } catch (err) {
      if (msgEl) {
        msgEl.className = "p-3 rounded-xl bg-rose-50 border border-rose-200 text-xs text-rose-700 font-medium";
        msgEl.textContent = err.message || "Mã xác thực không hợp lệ hoặc chưa được Admin phê duyệt!";
        msgEl.classList.remove("hidden");
      }
      this.showToast(err.message || "Lỗi đặt lại mật khẩu", "error");
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-unlock mr-1.5"></i>Xác Thực & Đặt Lại`;
      }
    }
  },

  handleForgotPasswordForm(e) {
    this.handleForgotPasswordConfirmForm(e);
  },

  async quickLogin(username, password) {
    const uInput = document.getElementById("login-username");
    const pInput = document.getElementById("login-password");
    if (uInput) uInput.value = username;
    if (pInput) pInput.value = password;
    await this.handleLoginForm();
  },

  async handleLogout() {
    try {
      await API.logout();
    } catch (ignored) {}
    this.showToast("Đã đăng xuất và thu hồi Token JWT an toàn.", "info");
    this.showLoginView();
    this.currentPath = "/";
  },

  togglePasswordVisibility() {
    const pInput = document.getElementById("login-password");
    const pIcon = document.getElementById("pwd-eye-icon");
    const pText = document.getElementById("pwd-toggle-text");
    if (!pInput) return;

    if (pInput.type === "password") {
      pInput.type = "text";
      if (pIcon) pIcon.className = "fa-solid fa-eye-slash text-sm";
      if (pText) pText.textContent = "Ẩn";
    } else {
      pInput.type = "password";
      if (pIcon) pIcon.className = "fa-solid fa-eye text-sm";
      if (pText) pText.textContent = "Hiện";
    }
  },

  // =========================================================================
  // SYSTEM & LAN / INTERNET NETWORK SHARING
  // =========================================================================
  async fetchSystemInfo() {
    try {
      const res = await API.getSystemStatus();
      if (res && res.lan_ip) {
        const port = res.port || window.location.port || 8080;
        this.lanUrl = `http://${res.lan_ip}:${port}/`;

        const loginLanDisplay = document.getElementById("login-lan-ip");
        const navLanDisplay = document.getElementById("nav-lan-ip");

        if (loginLanDisplay) loginLanDisplay.textContent = this.lanUrl;
        if (navLanDisplay) navLanDisplay.textContent = `http://${res.lan_ip}:${port}`;
      }

      // Nhận diện Public URL từ Cloudflare Tunnel hoặc URL hiện tại của trình duyệt
      let pub = res.public_url;
      if (!pub && (window.location.hostname.includes("trycloudflare.com") || window.location.protocol === "https:")) {
        pub = window.location.origin;
      }
      this.publicUrl = pub || "";

      const navPubUrl = document.getElementById("nav-public-url");
      const loginPubLink = document.getElementById("login-public-link");

      if (this.publicUrl) {
        if (navPubUrl) {
          navPubUrl.textContent = this.publicUrl.replace("https://", "").replace("http://", "");
          navPubUrl.title = this.publicUrl;
        }
        if (loginPubLink) {
          loginPubLink.textContent = this.publicUrl;
          loginPubLink.href = this.publicUrl;
        }
      }

      if (res && res.database) {
        const dbCount = document.getElementById("nav-db-count");
        if (dbCount) {
          dbCount.textContent = `${res.database.file_count || 0} tệp lưu`;
        }
      }
    } catch (e) {
      console.warn("Could not retrieve system status:", e);
    }
  },

  showRolesGuideModal() {
    this.showModal("modal-roles-guide");
  },

  async syncFilesSilently() {
    if (!this.currentPath || !API.getToken()) return;
    try {
      const res = await API.listFiles(this.currentPath);
      if (res && res.items) {
        const oldFingerprint = (this.rawItems || []).map(i => i.name + ":" + i.size + ":" + i.modified_at).join("|");
        const newFingerprint = res.items.map(i => i.name + ":" + i.size + ":" + i.modified_at).join("|");
        if (oldFingerprint !== newFingerprint) {
          this.rawItems = res.items;
          this.renderCurrentItems();
        }
      }
    } catch (e) {
      // Background sync, suppress errors
    }
  },

  copyLanUrl() {
    const url = this.lanUrl;
    navigator.clipboard.writeText(url).then(() => {
      this.showToast(`Đã sao chép liên kết mạng LAN: ${url}`, "success");
    }).catch(() => {
      prompt("Sao chép liên kết truy cập mạng LAN:", url);
    });
  },

  copyPublicUrl() {
    const url = this.publicUrl || (window.location.protocol === "https:" ? window.location.origin : "");
    if (!url) {
      this.showToast("Đang kích hoạt đường link Internet toàn cầu...", "warning");
      return;
    }
    navigator.clipboard.writeText(url).then(() => {
      this.showToast(`Đã sao chép link Internet (4G): ${url}`, "success");
    }).catch(() => {
      prompt("Sao chép link truy cập từ xa qua Internet (4G/Wi-Fi khác):", url);
    });
  },

  // =========================================================================
  // NAVIGATION & TABS
  // =========================================================================
  navigateToTab(tabId, path = null) {
    this.switchTab(tabId);
    if (path) {
      this.navigateTo(path);
    }
  },

  switchTab(tabId) {
    const tabs = ["files", "logs", "firewall", "antivirus", "acl", "users"];
    tabs.forEach(t => {
      const pane = document.getElementById(`tab-${t}`);
      const btn = document.getElementById(`tab-btn-${t}`);
      if (pane) {
        if (t === tabId) {
          pane.classList.remove("hidden");
        } else {
          pane.classList.add("hidden");
        }
      }
      if (btn) {
        if (t === tabId) {
          btn.className = "w-full flex items-center space-x-2.5 px-3 py-2.5 rounded-xl text-xs font-semibold text-blue-700 bg-blue-50 border border-blue-200 transition shadow-sm";
        } else {
          btn.className = "w-full flex items-center space-x-2.5 px-3 py-2.5 rounded-xl text-xs font-medium text-slate-700 hover:text-blue-600 hover:bg-slate-50 border border-transparent transition";
        }
      }
    });

    if (tabId === "logs") {
      this.loadAuditLogs();
      this.loadSOCStats();
    } else if (tabId === "firewall") {
      this.loadFirewallRules();
    } else if (tabId === "antivirus") {
      this.loadQuarantineRecords();
    } else if (tabId === "acl") {
      this.loadACLRules();
    } else if (tabId === "users") {
      this.loadSocUsers();
    }
  },

  updateSidebarActive(path) {
    const btnRoot = document.getElementById("sidebar-btn-root");
    const btnProj = document.getElementById("sidebar-btn-projects");
    const btnPol = document.getElementById("sidebar-btn-policies");
    const btnHr = document.getElementById("sidebar-btn-hr");

    const defaultClass = "sidebar-item w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-medium text-slate-700 hover:text-blue-600 hover:bg-slate-50 border border-transparent transition";
    const activeClass = "sidebar-item active w-full flex items-center justify-between px-3 py-2.5 rounded-xl text-xs font-semibold text-blue-700 bg-blue-50 border border-blue-200 transition shadow-sm";

    if (btnRoot) btnRoot.className = (path === "/" || path === "") ? activeClass : defaultClass;
    if (btnProj) btnProj.className = path.startsWith("/projects") ? activeClass : defaultClass;
    if (btnPol) btnPol.className = path.startsWith("/company_policies") ? activeClass : defaultClass;
    if (btnHr) btnHr.className = path.startsWith("/hr_confidential") ? activeClass : defaultClass;
  },

  // =========================================================================
  // VIEW MODE (GRID VS LIST)
  // =========================================================================
  setViewMode(mode) {
    this.viewMode = mode;
    localStorage.setItem("file_view_mode", mode);
    this.updateViewModeButtons();
    this.renderCurrentItems();
  },

  updateViewModeButtons() {
    const btnGrid = document.getElementById("btn-view-grid");
    const btnList = document.getElementById("btn-view-list");
    const gridContainer = document.getElementById("file-grid-container");
    const listContainer = document.getElementById("file-list-container");

    if (this.viewMode === "grid") {
      if (btnGrid) btnGrid.className = "p-1.5 rounded-lg text-xs text-blue-600 bg-white font-bold transition shadow-sm";
      if (btnList) btnList.className = "p-1.5 rounded-lg text-xs text-slate-500 hover:text-slate-900 font-medium transition";
      if (gridContainer) gridContainer.classList.remove("hidden");
      if (listContainer) listContainer.classList.add("hidden");
    } else {
      if (btnGrid) btnGrid.className = "p-1.5 rounded-lg text-xs text-slate-500 hover:text-slate-900 font-medium transition";
      if (btnList) btnList.className = "p-1.5 rounded-lg text-xs text-blue-600 bg-white font-bold transition shadow-sm";
      if (gridContainer) gridContainer.classList.add("hidden");
      if (listContainer) listContainer.classList.remove("hidden");
    }
  },

  // =========================================================================
  // FILE EXPLORER OPERATIONS
  // =========================================================================
  async loadFiles(path) {
    this.currentPath = path;
    this.renderBreadcrumbs(path);
    this.updateSidebarActive(path);

    const gridContainer = document.getElementById("file-grid-container");
    const tableBody = document.getElementById("file-table-body");

    const loadingHtml = `
      <div class="col-span-full py-12 flex flex-col items-center justify-center text-slate-500 space-y-3">
        <i class="fa-solid fa-spinner fa-spin text-3xl text-blue-600"></i>
        <span class="text-xs font-medium">Đang tải danh sách qua Reverse Proxy Gateway...</span>
      </div>
    `;
    if (gridContainer) gridContainer.innerHTML = loadingHtml;
    if (tableBody) tableBody.innerHTML = `<tr><td colspan="5" class="px-6 py-8 text-center text-slate-500"><i class="fa-solid fa-spinner fa-spin mr-2 text-blue-600"></i> Đang tải dữ liệu tệp tin qua Proxy Gateway...</td></tr>`;

    try {
      const res = await API.listFiles(path);
      this.rawItems = res.items || [];
      this.currentBadge = (res.permissions && res.permissions.badge) ? res.permissions.badge : "Unknown";

      this.updateFolderPermissionBadge(this.currentBadge);
      this.renderCurrentItems();

    } catch (err) {
      const is403 = (err.message || "").includes("403") || (err.message || "").includes("từ chối") || (err.message || "").includes("Forbidden");
      const user = API.getUser();
      const userRole = user ? user.role : "GUEST";
      const username = user ? user.username : "guest";

      const errHtml = `
        <div class="col-span-full py-12 px-6 text-center rounded-2xl bg-rose-50/70 border border-rose-200 text-rose-800 space-y-3">
          <div class="w-16 h-16 rounded-2xl bg-rose-100 text-rose-600 flex items-center justify-center text-3xl mx-auto shadow-sm">
            <i class="fa-solid fa-shield-xmark"></i>
          </div>
          <div class="font-extrabold text-base text-rose-900">${is403 ? "403 Bị Từ Chối - Không Có Thẩm Quyền Truy Cập" : "Lỗi Truy Cập Thư Mục"}</div>
          <div class="text-xs text-slate-700 max-w-lg mx-auto leading-relaxed">
            ${is403 
              ? `Tài khoản <strong>@${username}</strong> (${userRole}) không được phép truy cập vào thư mục <code>${path}</code> theo <strong>Quy tắc Phân quyền ACL (Explicit Deny)</strong>. Thư mục này chỉ dành riêng cho Quản trị viên (ADMIN).` 
              : (err.message || "Không thể tải danh sách tệp tin")}
          </div>
          <div class="pt-2 flex items-center justify-center space-x-3">
            <button onclick="App.navigateTo('/projects')" class="px-4 py-2 rounded-xl bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 text-xs font-semibold shadow-sm transition">
              <i class="fa-solid fa-folder-open mr-1.5 text-blue-600"></i>Về Thư Mục Dự Án
            </button>
            <button onclick="App.showRolesGuideModal()" class="px-4 py-2 rounded-xl bg-purple-600 hover:bg-purple-700 text-white text-xs font-semibold shadow transition">
              <i class="fa-solid fa-users-gear mr-1.5"></i>Xem Bảng Phân Quyền
            </button>
          </div>
        </div>
      `;
      if (gridContainer) gridContainer.innerHTML = errHtml;
      if (tableBody) tableBody.innerHTML = `<tr><td colspan="5" class="px-6 py-10 text-center text-rose-600 font-semibold">${err.message}</td></tr>`;
      this.updateFolderPermissionBadge("Bị cấm truy cập (Denied)");
      this.showToast(err.message, "error");
    }
  },

  updateFolderPermissionBadge(badge) {
    const folderBadge = document.getElementById("folder-effective-badge");
    if (!folderBadge) return;

    folderBadge.textContent = badge;
    const isFull = badge.includes("Quản trị") || badge.includes("Admin") || badge.includes("Full");
    const isWrite = badge.includes("Ghi") || badge.includes("Write");
    const isReadOnly = badge.includes("Chỉ Đọc") || badge.includes("Read");

    if (isFull) {
      folderBadge.className = "font-bold ml-1.5 px-2.5 py-0.5 rounded-full text-xs bg-purple-50 text-purple-700 border border-purple-200";
    } else if (isWrite) {
      folderBadge.className = "font-bold ml-1.5 px-2.5 py-0.5 rounded-full text-xs bg-emerald-50 text-emerald-700 border border-emerald-200";
    } else if (isReadOnly) {
      folderBadge.className = "font-bold ml-1.5 px-2.5 py-0.5 rounded-full text-xs bg-amber-50 text-amber-700 border border-amber-200";
    } else {
      folderBadge.className = "font-bold ml-1.5 px-2.5 py-0.5 rounded-full text-xs bg-rose-50 text-rose-700 border border-rose-200";
    }

    // Dynamic Toolbar Button State (Enable/Disable based on write permission)
    const user = API.getUser();
    const canWrite = user && (user.role === "ADMIN" || isWrite);

    const btnNewFile = document.getElementById("btn-toolbar-new-file");
    const btnNewFolder = document.getElementById("btn-toolbar-new-folder");
    const btnUpload = document.getElementById("btn-toolbar-upload");

    [btnNewFile, btnNewFolder, btnUpload].forEach(btn => {
      if (!btn) return;
      if (canWrite) {
        btn.disabled = false;
        btn.classList.remove("opacity-40", "cursor-not-allowed");
        btn.removeAttribute("title");
      } else {
        btn.disabled = true;
        btn.classList.add("opacity-40", "cursor-not-allowed");
        btn.title = "Thư mục chỉ đọc hoặc tài khoản không có quyền Ghi trên ACL.";
      }
    });
  },

  renderBreadcrumbs(path) {
    const container = document.getElementById("file-breadcrumbs");
    if (!container) return;

    const parts = path.split("/").filter(p => p.length > 0);
    let html = `<button onclick="App.navigateTo('/')" class="hover:text-blue-600 font-bold px-1.5 py-0.5 rounded hover:bg-slate-100 text-slate-800 transition"><i class="fa-solid fa-house mr-1 text-blue-600"></i>Gốc (/)</button>`;
    let accum = "";

    parts.forEach(p => {
      accum += "/" + p;
      html += ` <span class="text-slate-400">/</span> <button onclick="App.navigateTo('${accum}')" class="hover:text-blue-600 font-bold px-1.5 py-0.5 rounded hover:bg-slate-100 text-slate-800 transition">${p}</button>`;
    });

    container.innerHTML = html;
  },

  handleSearchFiles(query) {
    const q = (query || "").trim().toLowerCase();
    if (!q) {
      this.renderCurrentItems(this.rawItems);
      return;
    }
    const filtered = this.rawItems.filter(it => it.name.toLowerCase().includes(q));
    this.renderCurrentItems(filtered);
  },

  renderCurrentItems(itemsToRender = null) {
    const items = itemsToRender !== null ? itemsToRender : this.rawItems;
    const gridContainer = document.getElementById("file-grid-container");
    const tableBody = document.getElementById("file-table-body");

    if (items.length === 0) {
      const emptyHtml = `
        <div class="col-span-full py-16 flex flex-col items-center justify-center text-slate-400 space-y-2">
          <i class="fa-regular fa-folder-open text-4xl text-slate-300 mb-1"></i>
          <span class="text-sm font-semibold text-slate-700">Thư mục hiện tại chưa có tệp tin nào.</span>
          <span class="text-xs text-slate-500">Nhấn nút "Tải lên" hoặc "Tạo tệp" để thêm dữ liệu mới.</span>
        </div>
      `;
      if (gridContainer) gridContainer.innerHTML = emptyHtml;
      if (tableBody) tableBody.innerHTML = `<tr><td colspan="5" class="px-6 py-12 text-center text-slate-500"><i class="fa-regular fa-folder-open text-3xl mb-2 block text-slate-400"></i>Thư mục trống.</td></tr>`;
      return;
    }

    // 1. Render Grid View Cards (White card with black text and blue accents)
    if (gridContainer) {
      const user = API.getUser();
      gridContainer.innerHTML = items.map(it => {
        const iconInfo = this.getFileIcon(it);
        const sizeStr = it.is_dir ? "Thư mục" : this.formatSize(it.size);
        const itemBadge = (it.permissions && it.permissions.badge) ? it.permissions.badge : this.currentBadge;
        const badgeColor = this.getBadgeColorClass(itemBadge);

        const canEditFile = user && (user.role === "ADMIN" || itemBadge.includes("Ghi") || itemBadge.includes("Admin"));
        const canDeleteFile = user && (user.role === "ADMIN" || itemBadge.includes("Ghi") || itemBadge.includes("Admin"));

        return `
          <div class="file-card group bg-white rounded-2xl p-4 flex flex-col justify-between hover:border-blue-400 hover:shadow-md transition relative text-slate-900 border border-slate-200">
            <div class="cursor-pointer" onclick="${it.is_dir ? `App.navigateTo('${it.path}')` : `App.previewFile('${it.path}')`}">
              <!-- Icon & Badge -->
              <div class="flex items-start justify-between mb-3">
                <div class="w-12 h-12 rounded-xl bg-blue-50 flex items-center justify-center border border-blue-100 shadow-sm">
                  ${iconInfo.html}
                </div>
                <span class="text-[10px] px-2 py-0.5 rounded-full font-bold ${badgeColor} truncate max-w-[100px]" title="${itemBadge}">
                  ${itemBadge}
                </span>
              </div>

              <!-- Name & Metadata (Black text) -->
              <div class="font-bold text-xs sm:text-sm text-slate-900 group-hover:text-blue-600 transition truncate" title="${it.name}">
                ${it.name}
              </div>
              <div class="text-[11px] text-slate-500 mt-1 flex items-center justify-between font-mono">
                <span>${sizeStr}</span>
                <span class="truncate ml-1" title="${it.modified_at}">${it.modified_at ? it.modified_at.split(" ")[0] : ""}</span>
              </div>
            </div>

            <!-- Action Buttons Footer -->
            <div class="border-t border-slate-100 mt-3 pt-2.5 flex items-center justify-end space-x-1">
              ${!it.is_dir ? `
                <button onclick="App.previewFile('${it.path}')" class="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500 hover:text-blue-600 transition" title="Xem nội dung">
                  <i class="fa-solid fa-eye text-xs"></i>
                </button>
                ${canEditFile ? `
                <button onclick="App.editFile('${it.path}')" class="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500 hover:text-amber-600 transition" title="Chỉnh sửa">
                  <i class="fa-solid fa-pen-to-square text-xs"></i>
                </button>` : ``}
                <button onclick="App.downloadFile('${it.path}', '${it.name}')" class="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500 hover:text-emerald-600 transition" title="Tải xuống">
                  <i class="fa-solid fa-download text-xs"></i>
                </button>
              ` : `
                <button onclick="App.navigateTo('${it.path}')" class="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500 hover:text-blue-600 transition" title="Mở thư mục">
                  <i class="fa-solid fa-arrow-right-to-bracket text-xs"></i>
                </button>
              `}
              ${canDeleteFile ? `
              <button onclick="App.deleteResource('${it.path}')" class="p-1.5 rounded-lg hover:bg-rose-50 text-slate-500 hover:text-rose-600 transition" title="Xóa tài nguyên">
                <i class="fa-solid fa-trash-can text-xs"></i>
              </button>` : ``}
            </div>
          </div>
        `;
      }).join("");
    }

    // 2. Render List View Rows (White table with black text)
    if (tableBody) {
      const user = API.getUser();
      tableBody.innerHTML = items.map(it => {
        const iconInfo = this.getFileIcon(it);
        const itemBadge = (it.permissions && it.permissions.badge) ? it.permissions.badge : this.currentBadge;
        const badgeColor = this.getBadgeColorClass(itemBadge);
        const sizeStr = it.is_dir ? "-" : this.formatSize(it.size);

        const canEditFile = user && (user.role === "ADMIN" || itemBadge.includes("Ghi") || itemBadge.includes("Admin"));
        const canDeleteFile = user && (user.role === "ADMIN" || itemBadge.includes("Ghi") || itemBadge.includes("Admin"));

        return `
          <tr class="hover:bg-blue-50/40 transition">
            <td class="px-5 py-3 font-semibold text-slate-900 flex items-center space-x-3 cursor-pointer" onclick="${it.is_dir ? `App.navigateTo('${it.path}')` : `App.previewFile('${it.path}')`}">
              <span class="w-6 text-center">${iconInfo.smallHtml}</span>
              <span class="hover:text-blue-600 transition">${it.name}</span>
            </td>
            <td class="px-5 py-3">
              <span class="text-[11px] px-2.5 py-0.5 rounded-full font-bold ${badgeColor}">
                ${itemBadge}
              </span>
            </td>
            <td class="px-5 py-3 text-xs text-slate-600 font-mono">${sizeStr}</td>
            <td class="px-5 py-3 text-xs text-slate-600 font-mono">${it.modified_at || "-"}</td>
            <td class="px-5 py-3 text-right space-x-1">
              ${!it.is_dir ? `
                <button onclick="App.previewFile('${it.path}')" class="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500 hover:text-blue-600 transition" title="Xem nội dung">
                  <i class="fa-solid fa-eye text-xs"></i>
                </button>
                ${canEditFile ? `
                <button onclick="App.editFile('${it.path}')" class="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500 hover:text-amber-600 transition" title="Chỉnh sửa">
                  <i class="fa-solid fa-pen-to-square text-xs"></i>
                </button>` : ``}
                <button onclick="App.downloadFile('${it.path}', '${it.name}')" class="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500 hover:text-emerald-600 transition" title="Tải xuống">
                  <i class="fa-solid fa-download text-xs"></i>
                </button>
              ` : `
                <button onclick="App.navigateTo('${it.path}')" class="p-1.5 rounded-lg hover:bg-slate-100 text-slate-500 hover:text-blue-600 transition" title="Mở thư mục">
                  <i class="fa-solid fa-arrow-right-to-bracket text-xs"></i>
                </button>
              `}
              ${canDeleteFile ? `
              <button onclick="App.deleteResource('${it.path}')" class="p-1.5 rounded-lg hover:bg-rose-50 text-slate-500 hover:text-rose-600 transition" title="Xóa">
                <i class="fa-solid fa-trash-can text-xs"></i>
              </button>` : ``}
            </td>
          </tr>
        `;
      }).join("");
    }
  },

  getFileIcon(item) {
    if (item.is_dir) {
      return {
        html: `<i class="fa-solid fa-folder text-amber-500 text-2xl"></i>`,
        smallHtml: `<i class="fa-solid fa-folder text-amber-500 text-base"></i>`
      };
    }
    const name = item.name.toLowerCase();
    if (name.endsWith(".txt") || name.endsWith(".md") || name.endsWith(".log")) {
      return {
        html: `<i class="fa-solid fa-file-lines text-blue-600 text-2xl"></i>`,
        smallHtml: `<i class="fa-solid fa-file-lines text-blue-600 text-base"></i>`
      };
    }
    if (name.endsWith(".py") || name.endsWith(".java") || name.endsWith(".js") || name.endsWith(".html") || name.endsWith(".css") || name.endsWith(".json")) {
      return {
        html: `<i class="fa-solid fa-file-code text-indigo-600 text-2xl"></i>`,
        smallHtml: `<i class="fa-solid fa-file-code text-indigo-600 text-base"></i>`
      };
    }
    if (name.endsWith(".zip") || name.endsWith(".tar") || name.endsWith(".gz") || name.endsWith(".rar") || name.endsWith(".7z")) {
      return {
        html: `<i class="fa-solid fa-file-zipper text-emerald-600 text-2xl"></i>`,
        smallHtml: `<i class="fa-solid fa-file-zipper text-emerald-600 text-base"></i>`
      };
    }
    if (name.endsWith(".exe") || name.endsWith(".bat") || name.endsWith(".infected")) {
      return {
        html: `<i class="fa-solid fa-biohazard text-rose-600 text-2xl"></i>`,
        smallHtml: `<i class="fa-solid fa-biohazard text-rose-600 text-base"></i>`
      };
    }
    return {
      html: `<i class="fa-solid fa-file text-slate-500 text-2xl"></i>`,
      smallHtml: `<i class="fa-solid fa-file text-slate-500 text-base"></i>`
    };
  },

  getBadgeColorClass(badge) {
    if (!badge) return "bg-slate-100 text-slate-700 border border-slate-200";
    if (badge.includes("Write") || badge.includes("Admin") || badge.includes("Full")) {
      return "bg-emerald-50 text-emerald-700 border border-emerald-200";
    }
    if (badge.includes("Read")) {
      return "bg-blue-50 text-blue-700 border border-blue-200";
    }
    return "bg-rose-50 text-rose-700 border border-rose-200";
  },

  formatSize(bytes) {
    if (bytes === undefined || bytes === null || bytes === 0) return "0 B";
    if (bytes < 1024) return bytes + " B";
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
    return (bytes / (1024 * 1024)).toFixed(2) + " MB";
  },

  navigateTo(path) {
    this.loadFiles(path);
  },

  refreshFiles() {
    this.loadFiles(this.currentPath);
  },

  // =========================================================================
  // FILE ACTIONS: PREVIEW, DOWNLOAD, EDIT, UPLOAD, CREATE, DELETE
  // =========================================================================
  async previewFile(path) {
    try {
      const res = await API.getFileContent(path);
      this.currentPreviewFile = path;
      const fileData = res.file || {};
      const fn = fileData.filename || path.split("/").filter(Boolean).pop() || path;
      const mime = fileData.mime_type || "application/octet-stream";
      const sizeStr = this.formatSize(fileData.size || 0);

      document.getElementById("preview-filename").textContent = fn;
      const pPath = document.getElementById("preview-path");
      if (pPath) pPath.textContent = path;
      const pSize = document.getElementById("preview-size");
      if (pSize) pSize.textContent = sizeStr;

      // Badges
      const typeBadge = document.getElementById("preview-type-badge");
      if (typeBadge) {
        let badgeText = "TỆP";
        if (fileData.is_image) badgeText = "HÌNH ẢNH";
        else if (fileData.is_pdf) badgeText = "PDF";
        else if (!fileData.is_binary) badgeText = "VĂN BẢN";
        else badgeText = "NHỊ PHÂN";
        typeBadge.textContent = badgeText;
      }

      // Metadata footer
      const metaUploader = document.getElementById("preview-meta-uploader");
      const metaDate = document.getElementById("preview-meta-date");
      const metaSha = document.getElementById("preview-meta-sha");
      if (metaUploader) metaUploader.textContent = `@${fileData.uploader || "system"}`;
      if (metaDate) metaDate.textContent = fileData.modified_at || "-";
      if (metaSha) metaSha.textContent = fileData.sha256 ? fileData.sha256.substring(0, 16) + "..." : "-";

      const imgWrap = document.getElementById("preview-image-wrap");
      const imgTag = document.getElementById("preview-image");
      const textPre = document.getElementById("preview-content");
      const binWrap = document.getElementById("preview-binary-wrap");
      const editBtn = document.getElementById("preview-edit-btn");

      // Permission check for editing
      const user = API.getUser();
      const canEdit = !fileData.is_binary && (user && (user.role === "ADMIN" || this.currentBadge.includes("Ghi")));
      if (editBtn) {
        if (canEdit) {
          editBtn.classList.remove("hidden");
        } else {
          editBtn.classList.add("hidden");
        }
      }

      if (fileData.is_image && fileData.content && fileData.content.startsWith("data:")) {
        // Image preview
        if (imgWrap) imgWrap.classList.remove("hidden");
        if (imgTag) imgTag.src = fileData.content;
        if (textPre) textPre.classList.add("hidden");
        if (binWrap) binWrap.classList.add("hidden");
      } else if (fileData.is_binary) {
        // Binary / PDF
        if (imgWrap) imgWrap.classList.add("hidden");
        if (textPre) textPre.classList.add("hidden");
        if (binWrap) binWrap.classList.remove("hidden");
      } else {
        // Text / Code
        if (imgWrap) imgWrap.classList.add("hidden");
        if (binWrap) binWrap.classList.add("hidden");
        if (textPre) {
          textPre.classList.remove("hidden");
          textPre.textContent = fileData.content || "";
        }
      }

      this.showModal("modal-preview");
    } catch (err) {
      this.showToast(err.message || "Không thể xem tệp tin", "error");
    }
  },

  editCurrentPreview() {
    if (!this.currentPreviewFile) return;
    this.hideModal("modal-preview");
    this.editFile(this.currentPreviewFile);
  },

  async downloadCurrentPreview() {
    if (!this.currentPreviewFile) return;
    const fn = this.currentPreviewFile.split("/").filter(Boolean).pop();
    await this.downloadFile(this.currentPreviewFile, fn);
  },

  async downloadFile(path, filename) {
    try {
      this.showToast(`Đang tải xuống "${filename}"...`, "info");
      await API.downloadFile(path, filename);
      this.showToast(`Đã tải xuống "${filename}" thành công!`, "success");
    } catch (err) {
      this.showToast(err.message || "Lỗi tải xuống tệp tin", "error");
    }
  },

  async editFile(path) {
    try {
      const res = await API.getFileContent(path);
      const fileData = res.file || {};
      if (fileData.is_binary) {
        this.showToast("Tệp tin nhị phân hoặc hình ảnh không hỗ trợ sửa văn bản trực tiếp.", "warning");
        return;
      }
      this.currentEditFile = path;
      document.getElementById("edit-filename").textContent = path;
      document.getElementById("edit-content").value = fileData.content || "";
      this.showModal("modal-edit");
    } catch (err) {
      this.showToast(err.message || "Không có quyền chỉnh sửa tệp", "error");
    }
  },

  async saveFileEdit() {
    if (!this.currentEditFile) return;
    const content = document.getElementById("edit-content").value;
    try {
      const res = await API.writeFile(this.currentEditFile, "", content);
      this.hideModal("modal-edit");
      this.showToast(res.message || "Lưu tệp tin thành công!", "success");
      this.refreshFiles();
    } catch (err) {
      this.showToast(err.message || "Lỗi lưu tệp tin", "error");
    }
  },

  showUploadModal() {
    document.getElementById("upload-target-path").value = this.currentPath;
    document.getElementById("upload-file-input").value = "";
    this.showModal("modal-upload");
  },

  async handleFileUpload() {
    const fileInput = document.getElementById("upload-file-input");
    const targetPath = document.getElementById("upload-target-path").value;
    const btn = document.getElementById("btn-upload-confirm");

    if (!fileInput.files || fileInput.files.length === 0) {
      this.showToast("Vui lòng chọn một tệp tin để tải lên.", "warning");
      return;
    }

    const file = fileInput.files[0];
    if (btn) {
      btn.disabled = true;
      btn.innerHTML = `<i class="fa-solid fa-spinner fa-spin mr-2"></i>Đang quét Antivirus & Tải lên...`;
    }

    try {
      const res = await API.uploadFile(file, targetPath);
      this.hideModal("modal-upload");
      this.showToast(res.message || `Đã tải lên "${file.name}" an toàn!`, "success");
      this.refreshFiles();
      this.loadQuarantineCount();
    } catch (err) {
      this.showToast(err.message || "Tải lên bị chặn bởi Antivirus/Firewall", "error");
      this.loadQuarantineCount();
    } finally {
      if (btn) {
        btn.disabled = false;
        btn.innerHTML = `Xác nhận Tải Lên`;
      }
    }
  },

  showNewFileModal() {
    document.getElementById("new-file-name").value = "";
    document.getElementById("new-file-content").value = "";
    this.showModal("modal-new-file");
  },

  async handleCreateFile() {
    const filename = document.getElementById("new-file-name").value.trim();
    const content = document.getElementById("new-file-content").value;

    if (!filename) {
      this.showToast("Tên tệp tin không được để trống.", "warning");
      return;
    }

    try {
      const res = await API.writeFile(this.currentPath, filename, content);
      this.hideModal("modal-new-file");
      this.showToast(res.message || "Tạo tệp thành công!", "success");
      this.refreshFiles();
    } catch (err) {
      this.showToast(err.message || "Không thể tạo tệp", "error");
    }
  },

  showNewFolderModal() {
    document.getElementById("new-folder-name").value = "";
    this.showModal("modal-new-folder");
  },

  async handleCreateFolder() {
    const dirName = document.getElementById("new-folder-name").value.trim();
    if (!dirName) {
      this.showToast("Tên thư mục không được để trống.", "warning");
      return;
    }

    try {
      const res = await API.mkdir(this.currentPath, dirName);
      this.hideModal("modal-new-folder");
      this.showToast(res.message || "Tạo thư mục thành công!", "success");
      this.refreshFiles();
    } catch (err) {
      this.showToast(err.message || "Không thể tạo thư mục", "error");
    }
  },

  async deleteResource(path) {
    const fn = path.split("/").filter(Boolean).pop() || path;
    if (!confirm(`Bạn có chắc chắn muốn xóa "${fn}"?\nThao tác này sẽ kiểm tra quyền DELETE trên ACL.`)) {
      return;
    }

    try {
      const res = await API.deleteFile(path);
      this.showToast(res.message || "Xóa thành công!", "success");
      this.refreshFiles();
    } catch (err) {
      this.showToast(err.message || "Không có quyền xóa tài nguyên", "error");
    }
  },

  // =========================================================================
  // DRAG & DROP FILE UPLOAD
  // =========================================================================
  initDragAndDrop() {
    const dropZone = document.getElementById("drop-zone");
    const overlay = document.getElementById("drag-drop-overlay");
    if (!dropZone || !overlay) return;

    let dragCounter = 0;

    window.addEventListener("dragenter", (e) => {
      e.preventDefault();
      dragCounter++;
      overlay.classList.add("active");
    });

    window.addEventListener("dragleave", (e) => {
      e.preventDefault();
      dragCounter--;
      if (dragCounter <= 0) {
        dragCounter = 0;
        overlay.classList.remove("active");
      }
    });

    window.addEventListener("dragover", (e) => {
      e.preventDefault();
    });

    window.addEventListener("drop", async (e) => {
      e.preventDefault();
      dragCounter = 0;
      overlay.classList.remove("active");

      const files = e.dataTransfer.files;
      if (!files || files.length === 0) return;

      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        this.showToast(`Đang tải lên "${file.name}"...`, "info");
        try {
          await API.uploadFile(file, this.currentPath);
          this.showToast(`Đã tải lên "${file.name}" thành công!`, "success");
        } catch (err) {
          this.showToast(err.message || `Lỗi tải lên "${file.name}"`, "error");
        }
      }
      this.refreshFiles();
      this.loadQuarantineCount();
    });
  },

  // =========================================================================
  // SOC AUDIT LOGS, STATS & QUARANTINE
  // =========================================================================
  async loadAuditLogs() {
    const filterEl = document.getElementById("log-status-filter");
    const status = filterEl ? filterEl.value : "ALL";
    const tbody = document.getElementById("audit-log-body");
    if (!tbody) return;

    try {
      const res = await API.getAuditLogs(status, 100);
      const logs = res.logs || [];

      if (logs.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" class="px-4 py-8 text-center text-slate-400 font-medium">Chưa có bản ghi nhật ký nào.</td></tr>`;
        return;
      }

      tbody.innerHTML = logs.map(l => {
        let statusBadge = "";
        if (l.status === "ALLOWED") {
          statusBadge = `<span class="px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold">ALLOWED</span>`;
        } else if (l.status === "DENIED_AUTHZ") {
          statusBadge = `<span class="px-2 py-0.5 rounded bg-amber-50 text-amber-700 border border-amber-200 font-bold">DENIED_AUTHZ</span>`;
        } else if (l.status === "BLOCKED_FIREWALL") {
          statusBadge = `<span class="px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-bold">BLOCKED_FIREWALL</span>`;
        } else if (l.status === "BLOCKED_PROXY") {
          statusBadge = `<span class="px-2 py-0.5 rounded bg-rose-50 text-rose-700 border border-rose-200 font-bold">BLOCKED_PROXY</span>`;
        } else if (l.status === "QUARANTINED_AV") {
          statusBadge = `<span class="px-2 py-0.5 rounded bg-purple-50 text-purple-700 border border-purple-200 font-bold">QUARANTINED_AV</span>`;
        } else {
          statusBadge = `<span class="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-bold">${l.status}</span>`;
        }

        return `
          <tr class="hover:bg-blue-50/30 text-slate-800">
            <td class="px-4 py-2.5 text-slate-500 whitespace-nowrap">${l.created_at || l.formatted_time || "-"}</td>
            <td class="px-4 py-2.5 text-blue-600 font-mono font-bold">${l.request_id}</td>
            <td class="px-4 py-2.5 text-slate-700">${l.client_ip}</td>
            <td class="px-4 py-2.5 text-slate-900 font-bold">${l.username || "ANONYMOUS"}</td>
            <td class="px-4 py-2.5 text-slate-800 font-bold">${l.action}</td>
            <td class="px-4 py-2.5 text-slate-600 font-mono">${l.resource_path || "-"}</td>
            <td class="px-4 py-2.5">${statusBadge}</td>
            <td class="px-4 py-2.5 text-slate-600 max-w-xs truncate" title="${l.reason || ''}">${l.reason || "-"}</td>
          </tr>
        `;
      }).join("");

    } catch (err) {
      console.error("Failed to load audit logs:", err);
    }
  },

  async loadSOCStats() {
    try {
      const res = await API.getSOCStats();
      const elTotal = document.getElementById("stat-total");
      const elAllowed = document.getElementById("stat-allowed");
      const elAuthz = document.getElementById("stat-authz-denied");
      const elFw = document.getElementById("stat-firewall-blocked");
      const elAv = document.getElementById("stat-av-quarantined");

      if (elTotal) elTotal.textContent = res.total_requests || 0;
      if (elAllowed) elAllowed.textContent = res.allowed_requests || 0;
      if (elAuthz) elAuthz.textContent = res.authz_denied || 0;
      if (elFw) elFw.textContent = res.firewall_blocked || 0;
      if (elAv) elAv.textContent = res.antivirus_quarantined || 0;
    } catch (ignored) {}
  },

  async loadQuarantineCount() {
    try {
      const res = await API.getQuarantineRecords();
      const count = (res.records || []).length;
      const countBadge = document.getElementById("sidebar-quarantine-count");
      if (countBadge) countBadge.textContent = count;
    } catch (ignored) {}
  },

  toggleAutoRefreshLogs(enabled) {
    if (this.logRefreshInterval) {
      clearInterval(this.logRefreshInterval);
      this.logRefreshInterval = null;
    }
    if (enabled) {
      this.logRefreshInterval = setInterval(() => {
        const pane = document.getElementById("tab-logs");
        if (pane && !pane.classList.contains("hidden")) {
          this.loadAuditLogs();
          this.loadSOCStats();
        }
      }, 3000);
    }
  },

  // =========================================================================
  // FIREWALL RULES & CONTROLS (Admin)
  // =========================================================================
  async loadFirewallRules() {
    const tbody = document.getElementById("firewall-rules-body");
    if (!tbody) return;

    try {
      const res = await API.getFirewallRules();
      const rules = res.rules || [];

      if (rules.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-slate-400 font-medium">Chưa có IP nào trong danh sách chặn/cho phép.</td></tr>`;
        return;
      }

      tbody.innerHTML = rules.map(r => `
        <tr class="hover:bg-slate-50 text-slate-800">
          <td class="px-4 py-3 text-slate-400">#${r.id}</td>
          <td class="px-4 py-3 text-slate-900 font-bold">${r.ip_address}</td>
          <td class="px-4 py-3">
            <span class="px-2 py-0.5 rounded text-[11px] font-bold ${r.rule_type === 'BLACKLIST' ? 'bg-rose-50 text-rose-700 border border-rose-200' : 'bg-emerald-50 text-emerald-700 border border-emerald-200'}">
              ${r.rule_type}
            </span>
          </td>
          <td class="px-4 py-3 text-slate-700">${r.reason || "-"}</td>
          <td class="px-4 py-3 text-slate-500 text-[11px] font-mono">${r.expires_at || "Vĩnh viễn"}</td>
          <td class="px-4 py-3 text-right">
            <button onclick="App.deleteFirewallRule(${r.id})" class="px-2.5 py-1 rounded bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 text-xs font-semibold transition">
              <i class="fa-solid fa-trash-can mr-1"></i> Xóa
            </button>
          </td>
        </tr>
      `).join("");

    } catch (err) {
      this.showToast(err.message, "error");
    }
  },

  showAddFirewallRuleModal() {
    document.getElementById("fw-new-ip").value = "";
    document.getElementById("fw-new-reason").value = "";
    this.showModal("modal-fw-rule");
  },

  async handleAddFirewallRule() {
    const ip = document.getElementById("fw-new-ip").value.trim();
    const type = document.getElementById("fw-new-type").value;
    const reason = document.getElementById("fw-new-reason").value.trim();

    if (!ip) {
      this.showToast("Địa chỉ IP không được để trống.", "warning");
      return;
    }

    try {
      const res = await API.addFirewallRule({
        ip_address: ip,
        rule_type: type,
        reason: reason || "Admin manual configuration"
      });
      this.hideModal("modal-fw-rule");
      this.showToast(res.message || "Đã áp dụng quy tắc Firewall!", "success");
      this.loadFirewallRules();
    } catch (err) {
      this.showToast(err.message, "error");
    }
  },

  async deleteFirewallRule(id) {
    if (!confirm(`Xóa quy tắc IP #${id}?`)) return;
    try {
      await API.deleteFirewallRule(id);
      this.showToast("Đã xóa quy tắc Firewall.", "info");
      this.loadFirewallRules();
    } catch (err) {
      this.showToast(err.message, "error");
    }
  },

  // =========================================================================
  // ANTIVIRUS & QUARANTINE VAULT
  // =========================================================================
  async loadQuarantineRecords() {
    const tbody = document.getElementById("quarantine-records-body");
    if (!tbody) return;

    try {
      const res = await API.getQuarantineRecords();
      const records = res.records || [];
      this.loadQuarantineCount();

      if (records.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="px-4 py-8 text-center text-slate-500"><i class="fa-solid fa-shield-heart text-2xl text-emerald-500 mb-2 block"></i>Khu vực cách ly mã độc hiện đang sạch. Không có tệp nhiễm độc nào.</td></tr>`;
        return;
      }

      tbody.innerHTML = records.map(r => `
        <tr class="hover:bg-slate-50 text-slate-800">
          <td class="px-4 py-3 text-slate-900 font-bold flex items-center space-x-2">
            <i class="fa-solid fa-file-excel text-rose-500"></i>
            <span>${r.original_filename}</span>
          </td>
          <td class="px-4 py-3">
            <span class="px-2 py-0.5 rounded text-[11px] font-bold bg-purple-50 text-purple-700 border border-purple-200">
              ${r.threat_name}
            </span>
          </td>
          <td class="px-4 py-3 text-slate-700 font-medium">${r.detected_by_step}</td>
          <td class="px-4 py-3 text-slate-500 text-[11px] font-mono">${r.uploader_username}@${r.uploader_ip}</td>
          <td class="px-4 py-3 text-slate-500 text-[11px] font-mono">${r.created_at || r.formatted_time || "-"}</td>
          <td class="px-4 py-3 text-right">
            <button onclick="App.deleteQuarantineRecord('${r.id}')" class="px-2.5 py-1 rounded bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 text-xs font-semibold transition">
              <i class="fa-solid fa-trash-can mr-1"></i> Tiêu hủy
            </button>
          </td>
        </tr>
      `).join("");

    } catch (err) {
      this.showToast(err.message, "error");
    }
  },

  async deleteQuarantineRecord(id) {
    if (!confirm(`Tiêu hủy vĩnh viễn mẫu mã độc trong khu cách ly (${id})?`)) return;
    try {
      await API.deleteQuarantineRecord(id);
      this.showToast("Mẫu mã độc đã được tiêu hủy.", "info");
      this.loadQuarantineRecords();
    } catch (err) {
      this.showToast(err.message, "error");
    }
  },

  // =========================================================================
  // ACL MATRIX & PERMISSIONS (Admin)
  // =========================================================================
  async loadACLRules() {
    const tbody = document.getElementById("acl-rules-body");
    if (!tbody) return;

    try {
      const res = await API.getACLRules();
      const rules = res.rules || [];

      if (rules.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="px-4 py-6 text-center text-slate-400 font-medium">Chưa có quy tắc ACL nào được thiết lập.</td></tr>`;
        return;
      }

      tbody.innerHTML = rules.map(r => {
        let subject = "-";
        if (r.user_id) {
          subject = `<span class="text-blue-600 font-bold"><i class="fa-solid fa-user mr-1"></i>User ID: ${r.user_id}</span>`;
        } else if (r.role) {
          subject = `<span class="text-purple-600 font-bold"><i class="fa-solid fa-users mr-1"></i>Role: ${r.role}</span>`;
        }

        const readCheck = r.can_read ? `<span class="text-emerald-600 font-bold">YES</span>` : `<span class="text-slate-300">NO</span>`;
        const writeCheck = r.can_write ? `<span class="text-emerald-600 font-bold">YES</span>` : `<span class="text-slate-300">NO</span>`;
        const deleteCheck = r.can_delete ? `<span class="text-emerald-600 font-bold">YES</span>` : `<span class="text-slate-300">NO</span>`;
        const denyCheck = r.is_deny ? `<span class="text-rose-600 font-bold">DENY</span>` : `<span class="text-emerald-600 font-bold">ALLOW</span>`;

        return `
          <tr class="hover:bg-slate-50 text-slate-800">
            <td class="px-4 py-3 text-slate-900 font-mono font-bold">${r.resource_path}</td>
            <td class="px-4 py-3">${subject}</td>
            <td class="px-4 py-3 text-center">${readCheck}</td>
            <td class="px-4 py-3 text-center">${writeCheck}</td>
            <td class="px-4 py-3 text-center">${deleteCheck}</td>
            <td class="px-4 py-3 text-center">${denyCheck}</td>
            <td class="px-4 py-3 text-right">
              <button onclick="App.deleteACLRule(${r.id})" class="px-2.5 py-1 rounded bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 text-xs font-semibold transition">
                <i class="fa-solid fa-trash-can mr-1"></i> Xóa
              </button>
            </td>
          </tr>
        `;
      }).join("");

    } catch (err) {
      this.showToast(err.message, "error");
    }
  },

  showAddACLRuleModal() {
    document.getElementById("acl-new-path").value = this.currentPath;
    document.getElementById("acl-can-read").checked = true;
    document.getElementById("acl-can-write").checked = false;
    document.getElementById("acl-can-delete").checked = false;
    document.getElementById("acl-is-deny").checked = false;
    this.showModal("modal-acl-rule");
  },

  async handleSaveACLRule() {
    const path = document.getElementById("acl-new-path").value.trim();
    const role = document.getElementById("acl-new-role").value;
    const canRead = document.getElementById("acl-can-read").checked;
    const canWrite = document.getElementById("acl-can-write").checked;
    const canDelete = document.getElementById("acl-can-delete").checked;
    const isDeny = document.getElementById("acl-is-deny").checked;

    if (!path) {
      this.showToast("Đường dẫn tài nguyên không được để trống.", "warning");
      return;
    }

    try {
      const res = await API.setACLRule({
        resource_path: path,
        role: role || null,
        can_read: canRead ? 1 : 0,
        can_write: canWrite ? 1 : 0,
        can_delete: canDelete ? 1 : 0,
        is_deny: isDeny ? 1 : 0
      });
      this.hideModal("modal-acl-rule");
      this.showToast(res.message || "Đã lưu quy tắc ACL!", "success");
      this.loadACLRules();
      this.refreshFiles();
    } catch (err) {
      this.showToast(err.message, "error");
    }
  },

  async deleteACLRule(id) {
    if (!confirm(`Xóa quy tắc ACL #${id}?`)) return;
    try {
      await API.deleteACLRule(id);
      this.showToast("Đã xóa quy tắc ACL.", "info");
      this.loadACLRules();
      this.refreshFiles();
    } catch (err) {
      this.showToast(err.message, "error");
    }
  },

  // =========================================================================
  // ADMIN USER MANAGEMENT & APPROVAL / LOCKOUT (SOC Section)
  // =========================================================================
  async loadSocUsers() {
    try {
      const res = await API.getUsers();
      this.rawSocUsers = res.users || [];

      // Cập nhật 4 ô thống kê
      const totalEl = document.getElementById("user-stat-total");
      const pendingEl = document.getElementById("user-stat-pending");
      const lockedEl = document.getElementById("user-stat-locked");
      const activeEl = document.getElementById("user-stat-active");

      let total = this.rawSocUsers.length;
      let pending = 0;
      let locked = 0;
      let active = 0;

      this.rawSocUsers.forEach(u => {
        const s = (u.status || "ACTIVE").toUpperCase();
        if (s === "PENDING") pending++;
        else if (s === "LOCKED") locked++;
        else active++;
      });

      if (totalEl) totalEl.textContent = total;
      if (pendingEl) pendingEl.textContent = pending;
      if (lockedEl) lockedEl.textContent = locked;
      if (activeEl) activeEl.textContent = active;

      this.renderSocUsers();
      this.loadPasswordResetRequests();
    } catch (err) {
      console.warn("Failed to load SOC users:", err);
      this.showToast(err.message || "Không thể tải danh sách tài khoản", "error");
    }
  },

  filterSocUsers(term) {
    this.socUserSearchTerm = (term || "").toLowerCase().trim();
    this.renderSocUsers();
  },

  filterSocUsersByStatus(status) {
    this.socUserStatusFilter = status;

    // Cập nhật giao diện nút lọc
    const buttons = document.querySelectorAll(".user-filter-btn");
    buttons.forEach(btn => {
      if (btn.getAttribute("onclick") && btn.getAttribute("onclick").includes(`'${status}'`)) {
        btn.className = "user-filter-btn px-2.5 py-1 rounded-lg bg-blue-50 text-blue-700 font-bold border border-blue-200 text-[11px] shadow-sm";
      } else {
        btn.className = "user-filter-btn px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-[11px]";
      }
    });

    this.renderSocUsers();
  },

  renderSocUsers() {
    const tbody = document.getElementById("soc-users-table-body");
    if (!tbody) return;

    let filtered = this.rawSocUsers;

    // 1. Lọc theo trạng thái
    if (this.socUserStatusFilter && this.socUserStatusFilter !== "ALL") {
      filtered = filtered.filter(u => (u.status || "ACTIVE").toUpperCase() === this.socUserStatusFilter);
    }

    // 2. Lọc theo từ khóa tìm kiếm
    if (this.socUserSearchTerm) {
      const q = this.socUserSearchTerm;
      filtered = filtered.filter(u => 
        (u.username && u.username.toLowerCase().includes(q)) ||
        (u.full_name && u.full_name.toLowerCase().includes(q)) ||
        (u.role && u.role.toLowerCase().includes(q))
      );
    }

    if (filtered.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="6" class="px-4 py-8 text-center text-slate-400">
            <i class="fa-solid fa-users-slash text-2xl mb-1 text-slate-300"></i>
            <div>Không có tài khoản nào phù hợp với bộ lọc hiện tại.</div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = filtered.map(u => {
      const status = (u.status || "ACTIVE").toUpperCase();
      const role = (u.role || "USER").toUpperCase();
      const failed = u.failed_attempts || 0;
      const isAdminRoot = u.username.toLowerCase() === "admin";

      // 1. Badge Vai trò
      let roleBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-blue-50 text-blue-700 border border-blue-200">KỸ SƯ (USER)</span>`;
      if (role === "ADMIN") {
        roleBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-50 text-purple-700 border border-purple-200">ADMIN (QUẢN TRỊ)</span>`;
      } else if (role === "GUEST") {
        roleBadge = `<span class="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200">KHÁCH (GUEST)</span>`;
      }

      // 2. Badge Trạng thái
      let statusBadge = `<span class="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200"><span class="w-2 h-2 rounded-full bg-emerald-500"></span><span>Hoạt Động</span></span>`;
      if (status === "PENDING") {
        statusBadge = `<span class="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-50 text-amber-800 border border-amber-300"><span class="w-2 h-2 rounded-full bg-amber-500 animate-ping"></span><span>Chờ Admin Duyệt</span></span>`;
      } else if (status === "LOCKED") {
        statusBadge = `<span class="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-50 text-rose-700 border border-rose-300"><i class="fa-solid fa-lock text-[10px]"></i><span>Bị Khóa (Sai 3 lần)</span></span>`;
      }

      // 3. Số lần nhập sai
      let failedBadge = `<span class="font-mono text-slate-400">0/3</span>`;
      if (status === "LOCKED" || failed >= 3) {
        failedBadge = `<span class="font-mono text-rose-600 font-bold bg-rose-50 px-2 py-0.5 rounded border border-rose-200">3/3 (Khóa)</span>`;
      } else if (failed > 0) {
        failedBadge = `<span class="font-mono text-amber-700 font-bold bg-amber-50 px-2 py-0.5 rounded border border-amber-200">${failed}/3</span>`;
      }

      // 4. Ngày đăng ký / Lý do khóa
      let infoText = `<span class="text-slate-500 font-mono text-[11px]">${u.registered_at || "-"}</span>`;
      if (status === "LOCKED" && u.lock_reason) {
        infoText = `
          <div>${infoText}</div>
          <div class="text-[10px] text-rose-600 font-medium italic mt-0.5"><i class="fa-solid fa-triangle-exclamation mr-1"></i>${u.lock_reason}</div>
        `;
      }

      // 5. Nút Thao tác Admin
      let actions = ``;
      if (status === "PENDING") {
        actions += `
          <button onclick="App.approveUser('${u.username}')" class="px-3 py-1.5 rounded-xl bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs shadow-sm transition flex items-center space-x-1.5" title="Phê duyệt tài khoản này">
            <i class="fa-solid fa-check"></i>
            <span>Duyệt Ngay</span>
          </button>
        `;
      } else if (status === "LOCKED") {
        actions += `
          <button onclick="App.unlockUser('${u.username}')" class="px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-sm transition flex items-center space-x-1.5" title="Mở khóa tài khoản bị nhập sai 3 lần">
            <i class="fa-solid fa-unlock"></i>
            <span>Mở Khóa</span>
          </button>
        `;
      } else if (!isAdminRoot) {
        actions += `
          <button onclick="App.openLockUserModal('${u.username}')" class="p-1.5 rounded-lg bg-amber-50 hover:bg-amber-100 text-amber-700 border border-amber-200 text-xs transition" title="Khóa tài khoản này">
            <i class="fa-solid fa-user-lock"></i>
          </button>
        `;
      }

      // Nút đổi mật khẩu & xóa
      actions += `
        <button onclick="App.openAdminResetPwdModal('${u.username}')" class="p-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 text-xs transition ml-1" title="Đặt lại mật khẩu">
          <i class="fa-solid fa-key"></i>
        </button>
      `;

      if (!isAdminRoot) {
        actions += `
          <button onclick="App.deleteUser('${u.username}')" class="p-1.5 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 text-xs transition ml-1" title="Xóa tài khoản">
            <i class="fa-solid fa-trash"></i>
          </button>
        `;
      }

      const initials = (u.full_name || u.username).slice(0, 2).toUpperCase();

      return `
        <tr class="hover:bg-slate-50/80 transition">
          <td class="px-4 py-3">
            <div class="flex items-center space-x-2.5">
              <div class="w-8 h-8 rounded-full bg-slate-100 border border-slate-200 flex items-center justify-center font-bold text-xs text-slate-700">
                ${initials}
              </div>
              <div>
                <div class="font-bold text-slate-900">${u.full_name || u.username}</div>
                <div class="font-mono text-[11px] text-slate-500">@${u.username}</div>
              </div>
            </div>
          </td>
          <td class="px-4 py-3">${roleBadge}</td>
          <td class="px-4 py-3">${statusBadge}</td>
          <td class="px-4 py-3 text-center">${failedBadge}</td>
          <td class="px-4 py-3">${infoText}</td>
          <td class="px-4 py-3 text-right">
            <div class="inline-flex items-center justify-end">
              ${actions}
            </div>
          </td>
        </tr>
      `;
    }).join("");
  },

  async approveUser(username) {
    try {
      await API.approveUser(username);
      this.showToast(`Đã phê duyệt tài khoản @${username}! Người dùng hiện có thể đăng nhập.`, "success");
      this.loadSocUsers();
    } catch (err) {
      this.showToast(err.message || "Lỗi phê duyệt tài khoản", "error");
    }
  },

  async unlockUser(username) {
    try {
      await API.unlockUser(username);
      this.showToast(`Đã mở khóa tài khoản @${username}! Số lần nhập sai đã được reset về 0.`, "success");
      this.loadSocUsers();
    } catch (err) {
      this.showToast(err.message || "Lỗi mở khóa tài khoản", "error");
    }
  },

  openLockUserModal(username) {
    const uInput = document.getElementById("admin-lock-username");
    const uDisp = document.getElementById("admin-lock-username-display");
    const rInput = document.getElementById("admin-lock-reason");

    if (uInput) uInput.value = username;
    if (uDisp) uDisp.textContent = `@${username}`;
    if (rInput) rInput.value = "Khóa an toàn bởi Quản trị viên";

    this.showModal("modal-admin-lock-user");
  },

  async handleAdminLockUserSubmit() {
    const username = document.getElementById("admin-lock-username")?.value;
    const reason = document.getElementById("admin-lock-reason")?.value;
    if (!username) return;

    try {
      await API.lockUser(username, reason);
      this.hideModal("modal-admin-lock-user");
      this.showToast(`Đã khóa tài khoản @${username} thành công.`, "warning");
      this.loadSocUsers();
    } catch (err) {
      this.showToast(err.message || "Lỗi khóa tài khoản", "error");
    }
  },

  openAdminResetPwdModal(username) {
    const uInput = document.getElementById("admin-reset-username");
    const uDisp = document.getElementById("admin-reset-username-display");
    const pInput = document.getElementById("admin-reset-new-pass");

    if (uInput) uInput.value = username;
    if (uDisp) uDisp.textContent = `@${username}`;
    if (pInput) pInput.value = "";

    this.showModal("modal-admin-reset-pwd");
  },

  async handleAdminResetPasswordSubmit() {
    const username = document.getElementById("admin-reset-username")?.value;
    const newPass = document.getElementById("admin-reset-new-pass")?.value;

    if (!username || !newPass || newPass.length < 4) {
      this.showToast("Mật khẩu mới phải có tối thiểu 4 ký tự.", "warning");
      return;
    }

    try {
      await API.resetUserPassword(username, newPass);
      this.hideModal("modal-admin-reset-pwd");
      this.showToast(`Đã đặt lại mật khẩu mới cho @${username}.`, "success");
      this.loadSocUsers();
    } catch (err) {
      this.showToast(err.message || "Lỗi đặt lại mật khẩu", "error");
    }
  },

  async deleteUser(username) {
    if (!confirm(`Bạn có chắc chắn muốn xóa tài khoản @${username} khỏi hệ thống?`)) return;

    try {
      await API.deleteUser(username);
      this.showToast(`Đã xóa tài khoản @${username}.`, "info");
      this.loadSocUsers();
    } catch (err) {
      this.showToast(err.message || "Lỗi xóa tài khoản", "error");
    }
  },

  // =========================================================================
  // PASSWORD RESET REQUESTS (ADMIN REVIEW & CODE APPROVAL)
  // =========================================================================
  async loadPasswordResetRequests() {
    try {
      const res = await API.getPasswordResetRequests();
      this.rawResetRequests = res.requests || [];
      this.renderPasswordResetRequests();
    } catch (err) {
      console.warn("Failed to load reset requests:", err);
    }
  },

  renderPasswordResetRequests() {
    const tbody = document.getElementById("soc-resets-table-body");
    if (!tbody) return;

    const list = this.rawResetRequests || [];
    if (list.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="5" class="px-4 py-8 text-center text-slate-400">
            <i class="fa-solid fa-clipboard-check text-2xl mb-1 text-slate-300"></i>
            <div>Hiện không có yêu cầu khôi phục mật khẩu nào.</div>
          </td>
        </tr>
      `;
      return;
    }

    tbody.innerHTML = list.map(r => {
      const status = (r.status || "PENDING").toUpperCase();
      let statusBadge = `<span class="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-amber-50 text-amber-800 border border-amber-300"><span class="w-2 h-2 rounded-full bg-amber-500 animate-ping"></span><span>Chờ Duyệt Cấp Mã</span></span>`;
      let actions = ``;

      if (status === "APPROVED") {
        statusBadge = `
          <div class="inline-flex items-center space-x-2">
            <span class="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-blue-50 text-blue-700 border border-blue-200">
              <i class="fa-solid fa-key text-[10px]"></i>
              <span>Mã OTP: <strong class="font-mono text-sm tracking-wider text-blue-800 select-all">${r.reset_code}</strong></span>
            </span>
          </div>
        `;
        actions = `
          <button onclick="App.showAdminOtpDisplay('${r.username}', '${r.reset_code}')" class="px-3 py-1.5 rounded-xl bg-blue-50 hover:bg-blue-100 text-blue-700 font-bold text-xs border border-blue-200 shadow-sm transition flex items-center space-x-1" title="Xem và Sao chép mã OTP">
            <i class="fa-regular fa-copy"></i>
            <span>Xem / Copy Mã</span>
          </button>
        `;
      } else if (status === "COMPLETED") {
        statusBadge = `<span class="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200"><i class="fa-solid fa-circle-check text-[10px]"></i><span>Đã Đặt Lại Thành Công</span></span>`;
        actions = `<span class="text-slate-400 text-[11px] font-mono">Hoàn tất</span>`;
      } else if (status === "REJECTED") {
        statusBadge = `<span class="inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-bold bg-rose-50 text-rose-700 border border-rose-200"><i class="fa-solid fa-ban text-[10px]"></i><span>Đã Từ Chối</span></span>`;
        actions = `<span class="text-slate-400 text-[11px] font-mono">Đã từ chối</span>`;
      } else {
        // PENDING
        actions = `
          <div class="inline-flex items-center space-x-1.5">
            <button onclick="App.approvePasswordReset('${r.username}')" class="px-3 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-700 text-white font-bold text-xs shadow-sm transition flex items-center space-x-1.5" title="Duyệt và cấp mã OTP 6 số">
              <i class="fa-solid fa-check"></i>
              <span>Duyệt & Cấp Mã</span>
            </button>
            <button onclick="App.rejectPasswordReset('${r.username}')" class="p-1.5 rounded-lg bg-rose-50 hover:bg-rose-100 text-rose-600 border border-rose-200 text-xs transition" title="Từ chối yêu cầu này">
              <i class="fa-solid fa-xmark"></i>
            </button>
          </div>
        `;
      }

      return `
        <tr class="hover:bg-slate-50/80 transition">
          <td class="px-4 py-3">
            <div class="font-bold text-slate-900">@${r.username}</div>
          </td>
          <td class="px-4 py-3 text-slate-600">${r.reason || "Quên mật khẩu"}</td>
          <td class="px-4 py-3 text-slate-500 font-mono text-[11px]">${r.requested_at || "-"}</td>
          <td class="px-4 py-3">${statusBadge}</td>
          <td class="px-4 py-3 text-right">
            <div class="inline-flex items-center justify-end">
              ${actions}
            </div>
          </td>
        </tr>
      `;
    }).join("");
  },

  async approvePasswordReset(username) {
    try {
      const res = await API.approvePasswordReset(username);
      this.showToast(`Đã duyệt yêu cầu cho @${username}! Mã OTP: ${res.reset_code}`, "success");
      this.showAdminOtpDisplay(username, res.reset_code);
      this.loadPasswordResetRequests();
    } catch (err) {
      this.showToast(err.message || "Lỗi phê duyệt yêu cầu", "error");
    }
  },

  async rejectPasswordReset(username) {
    if (!confirm(`Bạn có chắc chắn muốn từ chối yêu cầu khôi phục của @${username}?`)) return;
    try {
      await API.rejectPasswordReset(username);
      this.showToast(`Đã từ chối yêu cầu khôi phục của @${username}.`, "info");
      this.loadPasswordResetRequests();
    } catch (err) {
      this.showToast(err.message || "Lỗi từ chối yêu cầu", "error");
    }
  },

  showAdminOtpDisplay(username, code) {
    const uEl = document.getElementById("admin-otp-username");
    const cEl = document.getElementById("admin-otp-code-value");
    if (uEl) uEl.textContent = `@${username}`;
    if (cEl) cEl.textContent = code;
    this.currentAdminOtpCode = code;
    this.showModal("modal-admin-otp-display");
  },

  copyAdminOtpCode() {
    const code = this.currentAdminOtpCode || document.getElementById("admin-otp-code-value")?.textContent || "";
    if (code) {
      navigator.clipboard.writeText(code).then(() => {
        this.showToast(`Đã sao chép mã OTP (${code}) vào clipboard!`, "success");
      }).catch(() => {
        this.showToast(`Mã OTP: ${code}`, "info");
      });
    }
  },

  // =========================================================================
  // MODALS & TOAST NOTIFICATIONS (White Theme)
  // =========================================================================
  showModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove("hidden");
  },

  hideModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add("hidden");
  },

  showToast(message, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;

    const toast = document.createElement("div");
    let colorClasses = "bg-white border border-slate-200 border-l-4 border-l-blue-600 text-slate-900 shadow-xl";
    let icon = '<i class="fa-solid fa-circle-info mr-2 text-blue-600 text-sm"></i>';

    if (type === "success") {
      colorClasses = "bg-white border border-slate-200 border-l-4 border-l-emerald-500 text-slate-900 shadow-xl";
      icon = '<i class="fa-solid fa-circle-check mr-2 text-emerald-600 text-sm"></i>';
    } else if (type === "error") {
      colorClasses = "bg-white border border-slate-200 border-l-4 border-l-rose-500 text-slate-900 shadow-xl";
      icon = '<i class="fa-solid fa-triangle-exclamation mr-2 text-rose-600 text-sm"></i>';
    } else if (type === "warning") {
      colorClasses = "bg-white border border-slate-200 border-l-4 border-l-amber-500 text-slate-900 shadow-xl";
      icon = '<i class="fa-solid fa-circle-exclamation mr-2 text-amber-600 text-sm"></i>';
    }

    toast.className = `p-3.5 rounded-2xl text-xs flex items-center justify-between transition-all duration-300 transform translate-y-2 opacity-0 pointer-events-auto ${colorClasses}`;
    toast.innerHTML = `
      <div class="flex items-center space-x-2">
        ${icon}
        <span class="font-bold">${message}</span>
      </div>
      <button onclick="this.parentElement.remove()" class="text-slate-400 hover:text-slate-600 ml-3 p-1">
        <i class="fa-solid fa-xmark"></i>
      </button>
    `;

    container.appendChild(toast);

    setTimeout(() => {
      toast.classList.remove("translate-y-2", "opacity-0");
    }, 10);

    setTimeout(() => {
      toast.classList.add("opacity-0", "translate-y-2");
      setTimeout(() => toast.remove(), 300);
    }, 4500);
  }
};

// Bootstrap application on DOM ready
document.addEventListener("DOMContentLoaded", () => {
  App.init();
});
