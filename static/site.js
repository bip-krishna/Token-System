(function () {
  const THEME_KEY = "nitc-theme";
  const PROFILE_KEY = "nitc-student-profile";
  const AUTH_TOKEN_KEY = "nitc-auth-token";
  const ADMIN_HALL_ROLE_KEY = "nitc-admin-hall-role";

  const DEFAULT_CONFIG = {
    enableBackend: true,
    backendBaseUrl: "",
    // studentProfilePath: "/auth/student/me",
    // showStudentDetails: true,
    // studentName: "Arun Krishna",
    // studentRollNo: "B22CS001"
  };

  function getConfig() {
    return { ...DEFAULT_CONFIG, ...(window.APP_CONFIG || {}) };
  }

  function normalizeBaseUrl(url) {
    const raw = (url || "").trim();
    if (!raw || raw.includes("{{") || raw.includes("}}")) {
      return "";
    }
    return raw.replace(/\/+$/, "");
  }

  function getBackendBaseUrl() {
    const config = getConfig();
    const configUrl = normalizeBaseUrl(config.backendBaseUrl);
    if (configUrl) {
      return configUrl;
    }

    const bodyUrl = normalizeBaseUrl(document.body?.dataset?.backendBaseUrl);
    if (bodyUrl) {
      return bodyUrl;
    }

    const metaUrl = normalizeBaseUrl(document.querySelector('meta[name="backend-base-url"]')?.content);
    if (metaUrl) {
      return metaUrl;
    }

    return window.location.origin;
  }

  function parseJson(value) {
    if (!value) {
      return null;
    }
    try {
      return JSON.parse(value);
    } catch {
      return null;
    }
  }

  function getStoredProfile() {
    return parseJson(localStorage.getItem(PROFILE_KEY));
  }

  function saveStudentSession(payload) {
    if (payload?.token) {
      localStorage.setItem(AUTH_TOKEN_KEY, payload.token);
    }

    const profile = {
      name: payload?.name || payload?.studentName || "",
      email: payload?.email || "",
      rollNo: payload?.rollNo || payload?.roll_number || "",
      branch: payload?.branch || "",
      reportingDate: payload?.reportingDate || payload?.reporting_date || "",
      canBookToday: Boolean(payload?.canBookToday),
      bookingAllowed: payload?.bookingAllowed,
      hall: payload?.hall || ""
    };

    localStorage.setItem(PROFILE_KEY, JSON.stringify(profile));
    return profile;
  }

  function clearStudentSession() {
    localStorage.removeItem(PROFILE_KEY);
    localStorage.removeItem(AUTH_TOKEN_KEY);
    localStorage.removeItem(ADMIN_HALL_ROLE_KEY);
  }

  function normalizeProfilePayload(payload) {
    if (!payload || typeof payload !== "object") {
      return null;
    }

    return {
      name: payload.name || payload.studentName || payload.fullName || "",
      email: payload.email || "",
      rollNo: payload.rollNo || payload.roll_number || "",
      branch: payload.branch || payload.department || "",
      reportingDate: payload.reportingDate || payload.reporting_date || "",
      canBookToday: Boolean(payload.canBookToday),
      bookingAllowed: payload.bookingAllowed,
      hall: payload.hall || ""
    };
  }

  function parseYmd(value) {
    if (!value) {
      return null;
    }

    const raw = value.trim();
    const parts = raw.match(/^(\d{4})-(\d{2})-(\d{2})$/);
    if (!parts) {
      return null;
    }

    const year = Number(parts[1]);
    const month = Number(parts[2]);
    const day = Number(parts[3]);
    return new Date(year, month - 1, day);
  }

  function isBookingOpen(profile, now = new Date()) {
    if (!profile) {
      return false;
    }

    if (typeof profile.bookingAllowed === "boolean") {
      return profile.bookingAllowed;
    }

    if (profile.canBookToday) {
      return true;
    }

    const reportingDate = parseYmd(profile.reportingDate);
    if (!reportingDate) {
      return false;
    }

    const tomorrow = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);
    const sameDate =
      reportingDate.getFullYear() === tomorrow.getFullYear() &&
      reportingDate.getMonth() === tomorrow.getMonth() &&
      reportingDate.getDate() === tomorrow.getDate();

    return sameDate && now.getHours() >= 17;
  }

  function getInitialTheme() {
    const savedTheme = localStorage.getItem(THEME_KEY);
    if (savedTheme === "dark" || savedTheme === "light") {
      return savedTheme;
    }
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function applyTheme(theme) {
    const isDark = theme === "dark";
    document.documentElement.classList.toggle("dark", isDark);
    document.documentElement.classList.toggle("light", !isDark);
    localStorage.setItem(THEME_KEY, isDark ? "dark" : "light");

    const toggle = document.getElementById("global-theme-toggle");
    if (toggle) {
      toggle.checked = isDark;
    }
  }

  function applyStudentFields() {
    const config = getConfig();
    const profile = getStoredProfile();

    const name = profile?.name || document.body.dataset.studentName || config.studentName;
    const rollNo = profile?.rollNo || document.body.dataset.studentRollNo || config.studentRollNo;
    const branch = profile?.branch || document.body.dataset.studentBranch || "NA";

    document.body.dataset.studentName = name;
    document.body.dataset.studentRollNo = rollNo;
    document.body.dataset.studentBranch = branch;

    document.querySelectorAll("[data-student-field='name']").forEach((el) => {
      el.textContent = name;
    });
    document.querySelectorAll("[data-student-field='rollNo']").forEach((el) => {
      el.textContent = rollNo;
    });
    document.querySelectorAll("[data-student-field='branch']").forEach((el) => {
      el.textContent = branch;
    });
    document.querySelectorAll("[data-student-field='reportingDate']").forEach((el) => {
      el.textContent = profile?.reportingDate || "Not Assigned";
    });
  }

  function ensureSettingsPanel() {
    if (document.getElementById("global-settings-container")) {
      return;
    }

    const hideLogout = document.body?.dataset?.hideLogout === "true";
    const navbarMount = document.querySelector("[data-settings-mount]");
    const isNavbarMounted = Boolean(navbarMount);

    const containerClass = isNavbarMounted ? "relative z-[60]" : "fixed top-4 right-4 z-[60]";
    const buttonClass = isNavbarMounted
      ? "inline-flex items-center justify-center rounded-lg p-2 text-slate-500 hover:text-primary hover:bg-slate-100 dark:text-slate-300 dark:hover:text-primary dark:hover:bg-slate-800 transition-colors"
      : "inline-flex items-center gap-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm font-medium text-slate-700 dark:text-slate-200 shadow-sm hover:bg-slate-50 dark:hover:bg-slate-700 transition-colors";

    const container = document.createElement("div");
    container.id = "global-settings-container";
    container.className = containerClass;
    container.innerHTML = `
      <button id="global-settings-button" type="button" aria-label="Open settings" class="${buttonClass}">
        <span class="material-symbols-outlined text-[20px]">settings</span>
        ${isNavbarMounted ? "" : "Settings"}
      </button>
      <div id="global-settings-panel" class="hidden absolute right-0 mt-2 w-72 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-xl p-4 space-y-4">
        <div class="flex items-center justify-between">
          <span class="text-sm font-medium text-slate-700 dark:text-slate-200">Dark Mode</span>
          <label class="inline-flex cursor-pointer items-center">
            <input id="global-theme-toggle" type="checkbox" class="peer sr-only"/>
            <span class="h-6 w-11 rounded-full bg-slate-300 peer-checked:bg-primary transition-colors relative after:content-[''] after:absolute after:left-0.5 after:top-0.5 after:h-5 after:w-5 after:rounded-full after:bg-white after:transition-transform peer-checked:after:translate-x-5"></span>
          </label>
        </div>
        ${hideLogout ? "" : `
        <div class="pt-3 border-t border-slate-200 dark:border-slate-700">
          <button data-action="logout" type="button" class="w-full inline-flex items-center justify-center gap-2 rounded-lg border border-red-200 dark:border-red-900/50 bg-red-50 dark:bg-red-950/30 px-3 py-2 text-sm font-medium text-red-600 dark:text-red-300 hover:bg-red-100 dark:hover:bg-red-950/50 transition-colors">
            <span class="material-symbols-outlined text-[18px]">logout</span>
            Logout
          </button>
        </div>
        `}
      </div>
    `;

    if (isNavbarMounted) {
      navbarMount.appendChild(container);
    } else {
      document.body.appendChild(container);
    }

    const button = document.getElementById("global-settings-button");
    const panel = document.getElementById("global-settings-panel");
    const toggle = document.getElementById("global-theme-toggle");

    button.addEventListener("click", () => panel.classList.toggle("hidden"));
    toggle.addEventListener("change", (event) => applyTheme(event.target.checked ? "dark" : "light"));

    document.addEventListener("click", (event) => {
      if (!container.contains(event.target)) {
        panel.classList.add("hidden");
      }
    });

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        panel.classList.add("hidden");
      }
    });
  }

  function bindPasswordToggles() {
    document.querySelectorAll(".password-toggle").forEach((button) => {
      if (button.dataset.bound === "true") {
        return;
      }
      button.dataset.bound = "true";

      button.addEventListener("click", () => {
        const input = document.getElementById(button.dataset.target);
        if (!input) {
          return;
        }
        const icon = button.querySelector("span");
        const shouldReveal = input.type === "password";
        input.type = shouldReveal ? "text" : "password";
        if (icon) {
          icon.textContent = shouldReveal ? "visibility_off" : "visibility";
        }
        button.setAttribute("aria-label", shouldReveal ? "Hide password" : "Show password");
      });
    });
  }

  const AppAPI = {
    setBaseUrl(url) {
      window.APP_CONFIG = { ...(window.APP_CONFIG || {}), backendBaseUrl: url };
    },

    async request(path, options) {
      const config = getConfig();
      if (!config.enableBackend) {
        throw new Error("Backend integration is disabled. Set window.APP_CONFIG.enableBackend = true.");
      }

      const backendBaseUrl = getBackendBaseUrl();
      if (!backendBaseUrl) {
        throw new Error("Missing backend base URL. Set window.APP_CONFIG.backendBaseUrl from app.py.");
      }

      const token = localStorage.getItem(AUTH_TOKEN_KEY);
      const endpoint = `${backendBaseUrl}${path}`;
      const response = await fetch(endpoint, {
        method: options?.method || "GET",
        headers: {
          "Content-Type": "application/json",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...(options?.headers || {})
        },
        body: options?.body
      });

      const contentType = response.headers.get("content-type") || "";
      const data = contentType.includes("application/json") ? await response.json() : await response.text();

      if (!response.ok) {
        const message = typeof data === "object" && data && data.message ? data.message : `Request failed with status ${response.status}`;
        throw new Error(message);
      }

      return data;
    },

    async getStudentProfile() {
      const token = localStorage.getItem(AUTH_TOKEN_KEY);
      if (!token) {
        return null;
      }

      const config = getConfig();
      const primaryPath = (config.studentProfilePath || "/auth/student/me").trim();
      const fallbackPaths = ["/auth/student/profile", "/student/me", "/profile"];
      const pathsToTry = [primaryPath, ...fallbackPaths.filter((path) => path !== primaryPath)];

      for (const path of pathsToTry) {
        try {
          const response = await this.request(path, { method: "GET" });
          return normalizeProfilePayload(response);
        } catch {
          // Try next route. Some backends use different profile endpoints.
        }
      }

      return null;
    },

    loginStudent(payload) {
      return this.request("/login", {
        method: "POST",
        body: JSON.stringify({
          role: "student",
          email: payload?.email || "",
          password: payload?.password || ""
        })
      });
    },

    loginAdmin(payload) {
      return this.request("/login", {
        method: "POST",
        body: JSON.stringify({
          role: "admin",
          email: payload?.email || payload?.adminId || "",
          password: payload?.password || "",
          hallRole: payload?.hallRole || payload?.hall_role || payload?.hall || ""
        })
      });
    },

    requestPasswordReset(payload) {
      return this.request("/auth/password/forgot", {
        method: "POST",
        body: JSON.stringify(payload)
      });
    },

    bookToken(payload) {
      return this.request("/tokens/book", {
        method: "POST",
        body: JSON.stringify(payload)
      });
    }
  };

  async function handleFormSubmit(form, onSubmit, loadingText) {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();

      const submitButton = form.querySelector('button[type="submit"]');
      const previousLabel = submitButton ? submitButton.textContent : "";

      if (submitButton) {
        submitButton.disabled = true;
        submitButton.textContent = loadingText;
      }

      try {
        await onSubmit();
      } catch (error) {
        alert(error.message);
      } finally {
        if (submitButton) {
          submitButton.disabled = false;
          submitButton.textContent = previousLabel;
        }
      }
    });
  }

  function buildDemoStudent(email) {
    return {
      token: "demo-token",
      name: "Rahul Sharma",
      email,
      rollNo: "B230456CS",
      branch: "CSE",
      reportingDate: "2026-08-20",
      canBookToday: true
    };
  }

  function bindBackendForms() {
    const studentForm = document.getElementById("student-form");
    if (studentForm) {
      handleFormSubmit(
        studentForm,
        async () => {
          const email = document.getElementById("student-email")?.value || "";
          const password = document.getElementById("student-password")?.value || "";
          const config = getConfig();

          if (config.enableBackend) {
            const response = await fetch("/login", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                role: "student",
                email,
                password
              })
            }).then((res) => res.json());

            if (!response?.success) {
              throw new Error(response?.message || "Invalid student login");
            }

            window.location.href = response.redirect || "student.html";
            return;
          }

          const profile = saveStudentSession(buildDemoStudent(email));
          const target = isBookingOpen(profile) ? "student.html" : "dashboard.html";
          window.location.href = target;
        },
        "Signing in..."
      );
    }

    const adminForm = document.getElementById("admin-form");
    if (adminForm) {
      handleFormSubmit(
        adminForm,
        async () => {
          const email = document.getElementById("admin-id")?.value || "";
          const password = document.getElementById("admin-password")?.value || "";
          const hallRole = (document.getElementById("hall-role")?.value || "").toLowerCase();
          const config = getConfig();

          if (config.enableBackend) {
            const response = await fetch("/login", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                role: "admin",
                email,
                password,
                hallRole
              })
            }).then((res) => res.json());

            if (!response?.success) {
              throw new Error(response?.message || "Invalid admin login");
            }

            if (hallRole) {
              localStorage.setItem(ADMIN_HALL_ROLE_KEY, hallRole);
            }
            window.location.href = response.redirect || "admin.html";
            return;
          }

          if (hallRole) {
            localStorage.setItem(ADMIN_HALL_ROLE_KEY, hallRole);
          }
          localStorage.setItem(AUTH_TOKEN_KEY, "demo-admin");
          window.location.href = hallRole === "chanakya" ? "admin2.html" : "admin.html";
        },
        "Signing in..."
      );
    }

    const forgotForm = document.getElementById("forgot-form");
    if (forgotForm) {
      handleFormSubmit(
        forgotForm,
        async () => {
          const config = getConfig();
          if (config.enableBackend) {
            await AppAPI.requestPasswordReset({
              email: document.getElementById("reset-email")?.value || ""
            });
          }
          alert("If your email is registered, a reset link has been sent.");
        },
        "Sending..."
      );
    }
  }

  function bindLogout() {
    document.querySelectorAll("[data-action='logout']").forEach((button) => {
      button.addEventListener("click", async () => {
        clearStudentSession();
        try {
          await fetch("/logout", { method: "POST" });
        } catch {
          // Ignore network/logout API errors and still navigate to login screen.
        }
        window.location.href = "/";
      });
    });
  }

  async function syncStudentDetailsFromBackend() {
    const config = getConfig();
    if (!config.enableBackend) {
      return;
    }

    const remoteProfile = await AppAPI.getStudentProfile();
    if (!remoteProfile) {
      return;
    }

    const localProfile = getStoredProfile() || {};
    const mergedProfile = {
      ...localProfile,
      ...Object.fromEntries(
        Object.entries(remoteProfile).filter(([, value]) => value !== "" && value !== null && value !== undefined)
      )
    };

    localStorage.setItem(PROFILE_KEY, JSON.stringify(mergedProfile));
  }

  async function init() {
    applyTheme(getInitialTheme());
    await syncStudentDetailsFromBackend();
    applyStudentFields();
    ensureSettingsPanel();
    bindPasswordToggles();
    bindBackendForms();
    bindLogout();

    window.addEventListener("storage", (event) => {
      if (event.key === THEME_KEY && (event.newValue === "dark" || event.newValue === "light")) {
        applyTheme(event.newValue);
      }
    });
  }

  window.AppAPI = AppAPI;
  window.NITC = {
    getStoredProfile,
    saveStudentSession,
    clearStudentSession,
    isBookingOpen
  };

  document.addEventListener("DOMContentLoaded", init);
})();
