// dsh-human-intent Web Client. DSH settings slot + Better Sidebar approval
// panel. The approval UI shows the EXACT action; approving signs the
// intentHash via WebAuthn (verification happens host-side).
window.__ModuleLoader__.load({
  id: "dsh-human-intent",
  factory: (require) => {
    var module = { exports: {} };
    var exports = module.exports;
    const React = require("react");
    const { createElement: h, useEffect, useRef, useState } = React;

    const API = "/human-intent/api";
    const emptyState = { status: null, pending: [] };

    const styles = {
      root: { display: "flex", flexDirection: "column", gap: "12px", padding: "14px", minHeight: "100%", boxSizing: "border-box", color: "var(--dsw-alias-label-primary)", fontSize: "13px" },
      title: { margin: 0, fontSize: "14px", fontWeight: 650 },
      muted: { margin: 0, color: "var(--dsw-alias-label-tertiary)", fontSize: "12px", lineHeight: 1.55, wordBreak: "break-word" },
      group: { display: "flex", flexDirection: "column", gap: "8px", padding: "12px", border: "1px solid var(--dsw-alias-border-l2)", borderRadius: "10px", background: "var(--dsw-alias-bg-layer-2, transparent)" },
      row: { display: "flex", gap: "6px", alignItems: "center", flexWrap: "wrap" },
      button: { border: "1px solid var(--dsw-alias-border-l2)", borderRadius: "8px", padding: "6px 10px", background: "var(--dsw-alias-bg-layer-3)", color: "var(--dsw-alias-label-primary)", cursor: "pointer", font: "inherit", fontSize: "12px" },
      primary: { background: "var(--dsw-alias-state-business-primary)", color: "white", borderColor: "var(--dsw-alias-state-business-primary)" },
      danger: { color: "var(--dsw-alias-label-error)", borderColor: "var(--dsw-alias-label-error)" },
      mono: { fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", fontSize: "12px", wordBreak: "break-all" },
      badge: { display: "inline-flex", alignItems: "center", gap: "5px", fontSize: "11px", fontWeight: 700, textTransform: "uppercase", letterSpacing: ".05em", padding: "2px 8px", borderRadius: "6px", border: "1px solid currentColor" },
      grid: { display: "grid", gridTemplateColumns: "96px 1fr", gap: "4px 12px", alignItems: "baseline" },
      gridKey: { color: "var(--dsw-alias-label-tertiary)", fontSize: "11px" },
      pre: { margin: 0, padding: "10px", border: "1px solid var(--dsw-alias-border-l2)", borderRadius: "8px", background: "var(--dsw-alias-bg-layer-3)", maxHeight: "200px", overflow: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" },
      error: { margin: 0, color: "var(--dsw-alias-label-error)", fontSize: "12px", lineHeight: 1.5 },
      success: { margin: 0, color: "var(--dsw-alias-state-positive-primary, #2a9d68)", fontSize: "12px" },
    };

    const riskColor = { low: "var(--dsw-alias-state-positive-primary, #2a9d68)", medium: "#d29922", high: "#e07b39", critical: "var(--dsw-alias-label-error)" };

    function shieldIcon(size = 18) {
      return h("svg", { width: size, height: size, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round", strokeLinejoin: "round", "aria-hidden": "true" },
        h("path", { d: "M12 3 20 6v5c0 4.8-3.1 8.9-8 10-4.9-1.1-8-5.2-8-10V6l8-3Z" }),
        h("path", { d: "m8.5 12 2.2 2.2 4.8-4.8" }),
      );
    }

    async function request(path, method = "GET", value) {
      const response = await fetch(`${API}${path}`, {
        method,
        headers: value === undefined ? {} : { "content-type": "application/json" },
        body: value === undefined ? undefined : JSON.stringify(value),
      });
      const parsed = await response.json().catch(() => null);
      if (!response.ok || !parsed || parsed.ok !== true) throw new Error(parsed?.error || `HTTP ${response.status}`);
      return parsed;
    }

    function bufferToBase64url(buffer) {
      const bytes = new Uint8Array(buffer);
      let binary = "";
      for (let i = 0; i < bytes.length; i += 1) binary += String.fromCharCode(bytes[i]);
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    function base64urlToBuffer(value) {
      const padded = String(value).replace(/-/g, "+").replace(/_/g, "/");
      const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
      return bytes.buffer;
    }

    function startAuthentication(options) {
      return navigator.credentials.get({
        publicKey: {
          challenge: base64urlToBuffer(options.challenge),
          rpId: options.rpId,
          allowCredentials: (options.allowCredentials || []).map(function (item) {
            return { id: base64urlToBuffer(item.id), type: "public-key", transports: item.transports };
          }),
          timeout: options.timeout,
          userVerification: options.userVerification || "required",
        },
      }).then(function (assertion) {
        const response = assertion.response;
        return {
          id: assertion.id,
          rawId: bufferToBase64url(assertion.rawId),
          type: assertion.type,
          response: {
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
            authenticatorData: bufferToBase64url(response.authenticatorData),
            signature: bufferToBase64url(response.signature),
            userHandle: response.userHandle ? bufferToBase64url(response.userHandle) : null,
          },
        };
      });
    }

    function startRegistration(options) {
      return navigator.credentials.create({
        publicKey: {
          challenge: base64urlToBuffer(options.challenge),
          rp: options.rp,
          user: { id: base64urlToBuffer(options.user.id), name: options.user.name, displayName: options.user.displayName },
          pubKeyCredParams: options.pubKeyCredParams,
          timeout: options.timeout,
          authenticatorSelection: options.authenticatorSelection,
          attestation: options.attestation,
        },
      }).then(function (credential) {
        const response = credential.response;
        return {
          id: credential.id,
          rawId: bufferToBase64url(credential.rawId),
          type: credential.type,
          response: {
            clientDataJSON: bufferToBase64url(response.clientDataJSON),
            attestationObject: bufferToBase64url(response.attestationObject),
          },
        };
      });
    }

    function ActionDetails({ request }) {
      const action = request.action || {};
      const context = request.context || {};
      const risk = context.risk || "medium";
      return h("div", { style: styles.group },
        h("div", { style: styles.row },
          h("span", { style: { ...styles.badge, color: riskColor[risk] || riskColor.medium } }, risk + " risk"),
        ),
        h("div", { style: styles.grid },
          h("span", { style: styles.gridKey }, "Tool"), h("span", { style: styles.mono }, action.tool || "—"),
          action.operation ? h("span", { style: styles.gridKey }, "Operation") : null, action.operation ? h("span", { style: styles.mono }, action.operation) : null,
          action.target ? h("span", { style: styles.gridKey }, "Target") : null, action.target ? h("span", { style: styles.mono }, action.target) : null,
          context.reason ? h("span", { style: styles.gridKey }, "Reason") : null, context.reason ? h("span", null, context.reason) : null,
          h("span", { style: styles.gridKey }, "Expires"), h("span", { style: styles.mono }, new Date(request.expiresAt).toLocaleTimeString()),
          h("span", { style: styles.gridKey }, "Intent hash"), h("span", { style: styles.mono }, (request.intentHash || "").slice(0, 32) + "…"),
        ),
        h("div", null,
          h("p", { style: { ...styles.muted, marginBottom: "4px" } }, "Exact arguments (what will be signed):"),
          h("pre", { style: styles.pre }, JSON.stringify(action.arguments, null, 2)),
        ),
      );
    }

    function ApprovalCard({ request: current, onSettled }) {
      const [busy, setBusy] = useState("");
      const [error, setError] = useState("");
      const [notice, setNotice] = useState("");
      async function approve() {
        setBusy("approve"); setError(""); setNotice("waiting for the platform authenticator…");
        try {
          const options = await request(`/intent/${encodeURIComponent(current.requestId)}/options`);
          const assertion = await startAuthentication(options.options);
          await request(`/intent/${encodeURIComponent(current.requestId)}/approve`, "POST", { assertion });
          setNotice("");
          onSettled("approved");
        } catch (err) { setNotice(""); setError(String(err.message || err)); setBusy(""); }
      }
      async function deny() {
        setBusy("deny"); setError("");
        try {
          await request(`/intent/${encodeURIComponent(current.requestId)}/deny`, "POST", { reason: "denied from DSH panel" });
          onSettled("denied");
        } catch (err) { setError(String(err.message || err)); setBusy(""); }
      }
      return h("div", { style: styles.group },
        h("strong", null, "Agent requests authorization"),
        h(ActionDetails, { request: current }),
        h("div", { style: styles.row },
          h("button", { type: "button", style: { ...styles.button, ...styles.primary }, disabled: !!busy, onClick: approve }, busy === "approve" ? "waiting for passkey…" : "Approve with passkey"),
          h("button", { type: "button", style: { ...styles.button, ...styles.danger }, disabled: !!busy, onClick: deny }, busy === "deny" ? "…" : "Deny"),
        ),
        notice ? h("p", { style: styles.muted }, notice) : null,
        error ? h("p", { style: styles.error }, error) : null,
      );
    }

    function ApprovalPanel() {
      const [state, setState] = useState(emptyState);
      const [error, setError] = useState("");
      const [outcome, setOutcome] = useState("");
      const seen = useRef(new Set());
      useEffect(() => {
        let alive = true;
        function absorb(value) { if (alive) setState((current) => ({ ...current, ...value })); }
        request("/state").then(absorb).catch((err) => { if (alive) setError(err.message); });
        const events = new EventSource(`${API}/events`);
        events.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            if (message.type === "request-created" && message.request) {
              if (seen.current.has(message.request.requestId)) return;
              seen.current.add(message.request.requestId);
              absorb({ pending: [message.request, ...state.pending.filter((item) => item.requestId !== message.request.requestId)] });
            } else if (message.type === "request-settled") {
              absorb({ pending: state.pending.filter((item) => item.requestId !== message.requestId) });
            }
          } catch { /* ignore malformed events */ }
        };
        events.onerror = () => events.close();
        return () => { alive = false; events.close(); };
      }, [state.pending]);
      const current = state.pending[0];
      return h("div", { style: styles.root, "data-dsh-human-intent": "panel" },
        h("h2", { style: styles.title }, "Human Intent"),
        h("p", { style: styles.muted }, "AI can propose an action. Only a human can authorize it. Protected tools execute only after the exact action below is approved."),
        current
          ? h(ApprovalCard, {
              request: current,
              onSettled: (decision) => {
                setOutcome(decision === "approved" ? "Approved — the exact action may now execute once." : "Denied — the agent was told the human refused.");
                setState((s) => ({ ...s, pending: s.pending.filter((item) => item.requestId !== current.requestId) }));
                setTimeout(() => setOutcome(""), 8000);
              },
            })
          : h("p", { style: styles.muted }, outcome || "No pending authorization requests."),
        state.status && state.status.credentialCount === 0 ? h("div", { style: styles.group },
          h("strong", null, "No passkey registered"),
          h("p", { style: styles.muted }, "Open the standalone approval page or run `npm run serve` to register a passkey first."),
        ) : null,
        error ? h("p", { style: styles.error }, error) : null,
      );
    }

    function SettingsPanel() {
      const [state, setState] = useState(null);
      const [error, setError] = useState("");
      const [notice, setNotice] = useState("");
      useEffect(() => { request("/state").then(setState).catch((err) => setError(err.message)); }, []);
      if (!state) return h("div", { style: styles.root }, h("p", { style: styles.muted }, error || "正在读取设置…"));
      async function register() {
        setNotice(""); setError("");
        try {
          const options = await request("/register/options", "POST", {});
          const attestation = await startRegistration(options.options);
          await request("/register/verify", "POST", { attestation });
          const next = await request("/state");
          setState(next);
          setNotice("Passkey registered on this host.");
        } catch (err) { setError(String(err.message || err)); }
      }
      return h("div", { style: styles.root },
        h("h2", { style: styles.title }, "Human Intent"),
        h("p", { style: styles.muted }, "Human intent authorization for AI agents. Configure protected tools in the plugin config; authorization happens in the Human Intent panel."),
        h("div", { style: styles.group },
          h("strong", null, "Passkey"),
          h("p", { style: styles.muted }, state.status?.credentialCount > 0 ? `${state.status.credentialCount} credential(s) registered. Approvals use the platform authenticator (Touch ID / Windows Hello).` : "No passkey registered yet. Authorization requests cannot be approved until one exists."),
          state.status?.credentialCount === 0 ? h("button", { type: "button", style: { ...styles.button, ...styles.primary }, onClick: register }, "Register passkey") : null,
        ),
        h("div", { style: styles.group },
          h("strong", null, "Protected tools"),
          state.status?.policy?.length > 0
            ? h("ul", { style: { margin: 0, paddingLeft: "18px" }, ...{} }, state.status.policy.map((rule, index) => h("li", { key: index, style: styles.mono }, rule.tool, rule.risk ? ` (${rule.risk})` : "")))
            : h("p", { style: styles.muted }, "No protected tools configured. Add tool names or globs to protectedTools in the plugin config."),
        ),
        h("div", { style: styles.group },
          h("strong", null, "Status"),
          h("div", { style: styles.grid },
            h("span", { style: styles.gridKey }, "Method"), h("span", { style: styles.mono }, state.status?.method || "—"),
            h("span", { style: styles.gridKey }, "Pending"), h("span", { style: styles.mono }, String(state.status?.pendingCount ?? 0)),
            h("span", { style: styles.gridKey }, "Consumed"), h("span", { style: styles.mono }, String(state.status?.consumedCount ?? 0)),
          ),
        ),
        notice ? h("p", { style: styles.success }, notice) : null,
        error ? h("p", { style: styles.error }, error) : null,
      );
    }

    function HeaderButton(props) {
      const { onOpen } = props;
      return h("button", { type: "button", title: "打开 Human Intent", style: { border: 0, background: "none", color: "inherit", cursor: "pointer", font: "inherit", fontSize: "12px", padding: "2px 8px" }, onClick: () => onOpen?.() }, "◉ Human Intent");
    }

    function apply(ctx) {
      if (typeof ctx.effect === "function") {
        ctx.effect(() => {
          const style = document.createElement("style");
          style.textContent = "[data-dsh-human-intent] button:focus-visible{outline:2px solid var(--dsw-alias-state-business-primary);outline-offset:1px}";
          document.head.appendChild(style);
          return () => style.remove();
        });
      }
      if (typeof ctx.slots?.inject === "function") {
        ctx.slots.inject("settings.section", () => ctx.slots.register({ name: "settings.section", id: "dsh-human-intent", order: 105, label: "Human Intent", icon: shieldIcon }, SettingsPanel));
        const openPanel = () => { try { ctx.get?.("betterSidebar")?.open?.("dsh-human-intent:main"); } catch { /* optional sidebar */ } };
        ctx.slots.inject("conversation.session.header.actions", () => ctx.slots.register({ name: "conversation.session.header.actions", id: "dsh-human-intent", order: 105, inject: () => ({ onOpen: openPanel }) }, HeaderButton));
      }
      if (typeof ctx.inject === "function") {
        try {
          ctx.inject(["betterSidebar"], (ctx2) => {
            const service = ctx2?.betterSidebar;
            if (!service?.registerTab) return;
            const dispose = service.registerTab({ id: "dsh-human-intent:main", title: () => "Human Intent", icon: shieldIcon, order: 105, single: true, component: ApprovalPanel });
            return () => dispose?.();
          });
        } catch { /* 旧 Host 无 Better Sidebar 时使用设置入口 */ }
      }
    }

    exports.apply = apply;
    exports.inject = ["slots"];
    return module.exports;
  },
});
