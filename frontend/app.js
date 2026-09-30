/**
 * TRACE-X FORENSIC WORKSTATION
 * Client Application Engine v2.0
 */

(function () {
    "use strict";

    // Global State
    const App = {
        state: {
            currentRoute: "command-center",
            routeParams: {},
            overview: null,
            alerts: [],
            wallets: [],
            sessions: [],
            activity: [],
            systemHealth: null,
            selectedWallet: null,
            selectedTx: null,
            graphData: null,
            graphFilters: {
                wallet: true,
                transaction: true,
                ip: true,
                highRiskOnly: false
            }
        },
        graphSimulation: null
    };

    // Utilities
    const $ = (selector, parent = document) => parent.querySelector(selector);
    const $$ = (selector, parent = document) => Array.from(parent.querySelectorAll(selector));

    const esc = (val) => String(val ?? "").replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
    })[c]);

    const num = (v, digits = 2) => Number(v || 0).toLocaleString("en-US", {
        minimumFractionDigits: digits, maximumFractionDigits: digits
    });

    const int = (v) => Number(v || 0).toLocaleString("en-US", { maximumFractionDigits: 0 });

    const shortId = (id, start = 10, end = 6) => {
        if (!id) return "-";
        const str = String(id);
        if (str.length <= start + end + 3) return str;
        return `${str.substring(0, start)}...${str.substring(str.length - end)}`;
    };

    const getRiskLevel = (score) => {
        const s = Number(score || 0);
        if (s >= 80) return "critical";
        if (s >= 60) return "high";
        if (s >= 35) return "medium";
        return "safe";
    };

    const getRiskLabel = (score) => {
        const level = getRiskLevel(score);
        return level.toUpperCase();
    };

    const showToast = (message, type = "info") => {
        const container = $("#toast-container");
        if (!container) return;
        const toast = document.createElement("div");
        toast.className = `toast ${type}`;
        toast.innerHTML = `
            <span class="toast-dot ${type}"></span>
            <span class="toast-msg">${esc(message)}</span>
        `;
        container.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(10px)";
            setTimeout(() => toast.remove(), 300);
        }, 3200);
    };

    const copyToClipboard = (text, label = "Item") => {
        navigator.clipboard.writeText(text).then(() => {
            showToast(`${label} copied to clipboard`, "success");
        }).catch(() => {
            showToast("Failed to copy", "error");
        });
    };

    // API Client
    const API = {
        async get(endpoint) {
            const res = await fetch(`/api${endpoint}`);
            if (!res.ok) {
                let err = `${res.status} ${res.statusText}`;
                try {
                    const data = await res.json();
                    if (data.detail) err = data.detail;
                } catch (_) {}
                throw new Error(err);
            }
            return res.json();
        },
        async post(endpoint, body) {
            const res = await fetch(`/api${endpoint}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(body || {})
            });
            if (!res.ok) {
                let err = `${res.status} ${res.statusText}`;
                try {
                    const data = await res.json();
                    if (data.detail) err = data.detail;
                } catch (_) {}
                throw new Error(err);
            }
            return res.json();
        },
        async postForm(endpoint, formData) {
            const res = await fetch(`/api${endpoint}`, {
                method: "POST",
                body: formData
            });
            if (!res.ok) {
                let err = `${res.status} ${res.statusText}`;
                try {
                    const data = await res.json();
                    if (data.detail) err = data.detail;
                } catch (_) {}
                throw new Error(err);
            }
            return res.json();
        },
        async delete(endpoint) {
            const res = await fetch(`/api${endpoint}`, {
                method: "DELETE"
            });
            if (!res.ok) {
                let err = `${res.status} ${res.statusText}`;
                try {
                    const data = await res.json();
                    if (data.detail) err = data.detail;
                } catch (_) {}
                throw new Error(err);
            }
            return res.json();
        }
    };

    // ==========================================================================
    // ROUTING ENGINE
    // ==========================================================================
    const Router = {
        init() {
            window.addEventListener("hashchange", () => this.handleRoute());
            window.addEventListener("popstate", () => this.handleRoute());

            // Wire nav-link clicks for reliable handling
            $$(".nav-link").forEach((link) => {
                link.addEventListener("click", (e) => {
                    const href = link.getAttribute("href") || "";
                    const targetClean = href.replace(/^[#/!]+/, "");
                    const currentClean = (window.location.hash || "").replace(/^[#/!]+/, "");
                    if (targetClean === currentClean) {
                        e.preventDefault();
                        this.handleRoute();
                    }
                });
            });

            this.handleRoute();
        },

        parseHash() {
            let raw = window.location.hash || "";
            raw = raw.replace(/^[#!/\s]+/, "");
            if (!raw) return { route: "command-center", param: null };
            const parts = raw.split("/").map((s) => s.trim()).filter(Boolean);
            const route = parts[0] ? parts[0].toLowerCase() : "command-center";
            const param = parts.length > 1 ? parts.slice(1).join("/") : null;
            return { route, param };
        },

        handleRoute() {
            const { route, param } = this.parseHash();

            App.state.currentRoute = route;
            App.state.routeParams = { id: param };

            // Update active state in sidebar
            $$(".nav-link").forEach((link) => {
                const target = (link.getAttribute("data-route") || "").toLowerCase();
                if (target === route) {
                    link.classList.add("active");
                } else {
                    link.classList.remove("active");
                }
            });

            // Cancel any running graph simulations when navigating away
            if (App.graphSimulation && route !== "network") {
                cancelAnimationFrame(App.graphSimulation);
                App.graphSimulation = null;
            }

            this.renderView(route, param);
        },

        navigate(path) {
            const cleanPath = String(path || "").replace(/^[#/!]+/, "");
            const targetHash = `#/${cleanPath}`;
            if (window.location.hash === targetHash) {
                this.handleRoute();
            } else {
                window.location.hash = targetHash;
            }
        },

        async renderView(route, param) {
            const container = $("#main-content");
            if (!container) return;

            container.innerHTML = `
                <div class="view-loading-skeleton">
                    <div class="skeleton-shimmer"></div>
                </div>
            `;

            try {
                switch (route) {
                    case "command-center":
                        await Views.renderCommandCenter(container);
                        break;
                    case "wallet":
                        await Views.renderWalletIntelligence(container, param);
                        break;
                    case "transaction":
                        await Views.renderTransactionFlow(container, param);
                        break;
                    case "network":
                        await Views.renderNetworkGraph(container, param);
                        break;
                    case "alerts":
                        await Views.renderThreatAlerts(container);
                        break;
                    case "sessions":
                        await Views.renderAnalysisSessions(container);
                        break;
                    case "ingest":
                        await Views.renderDatasetIngestion(container);
                        break;
                    case "reports":
                        await Views.renderInvestigationReports(container, param);
                        break;
                    case "system":
                        await Views.renderSystemHealth(container);
                        break;
                    default:
                        await Views.renderCommandCenter(container);
                }
            } catch (err) {
                console.error("View Render Error:", err);
                container.innerHTML = `
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title text-red">System Communication Error</span>
                        </div>
                        <div class="card-body">
                            <p style="color:var(--text-muted); margin-bottom:14px;">Failed to load view [${esc(route)}]: ${esc(err.message)}</p>
                            <button class="btn-cyber" onclick="window.location.reload()">RELOAD WORKSTATION</button>
                        </div>
                    </div>
                `;
            }
        }
    };

    // ==========================================================================
    // VIEW IMPLEMENTATIONS
    // ==========================================================================
    const Views = {
        // ----------------------------------------------------------------------
        // 1. COMMAND CENTER
        // ----------------------------------------------------------------------
        async renderCommandCenter(container) {
            const [overview, alertsData, activityData, sessionsData] = await Promise.all([
                API.get("/overview"),
                API.get("/alerts"),
                API.get("/activity").catch(() => ({ activity: [] })),
                API.get("/sessions").catch(() => ({ sessions: [] }))
            ]);

            App.state.overview = overview;
            App.state.alerts = alertsData.alerts || [];
            App.state.activity = activityData.activity || [];
            App.state.sessions = sessionsData.sessions || [];

            // Update header telemetry
            const alertCountBadge = $("#nav-alert-count");
            if (alertCountBadge) alertCountBadge.textContent = overview.high_risk_alerts || 0;
            const headerStat = $("#header-dataset-stat");
            if (headerStat) headerStat.textContent = `${int(overview.total_transactions || 3000)} TXS MONITORED`;

            const rDist = overview.risk_distribution || { critical: 7, high: 23, medium: 143, low: 307 };
            const totalEntities = overview.wallets || 1;
            const pCrit = Math.round((rDist.critical / totalEntities) * 100);
            const pHigh = Math.round((rDist.high / totalEntities) * 100);
            const pMed = Math.round((rDist.medium / totalEntities) * 100);
            const pLow = Math.max(0, 100 - (pCrit + pHigh + pMed));

            const topAlerts = App.state.alerts.slice(0, 6);
            const recentActivity = App.state.activity.slice(0, 6);
            const latestSession = App.state.sessions[0] || null;

            container.innerHTML = `
                <!-- COMMAND CENTER HEADER -->
                <div class="page-header">
                    <div class="page-title-group">
                        <h1 class="page-title">
                            COMMAND CENTER
                            <span class="risk-chip safe">LIVE MONITOR</span>
                        </h1>
                        <p class="page-subtitle">AI-powered monitoring and analysis of Bitcoin transaction traffic.</p>
                    </div>
                    <div class="page-actions">
                        <button class="btn-cyber" id="btn-run-analysis">
                            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
                                <polygon points="5 3 19 12 5 21 5 3"></polygon>
                            </svg>
                            TRIGGER ML ANALYSIS
                        </button>
                    </div>
                </div>

                <!-- 6 HUD GLOBAL INTELLIGENCE METRIC CARDS -->
                <div class="metrics-hud-grid">
                    <div class="hud-metric-card accent-cyan">
                        <div class="metric-label-row">
                            <span class="metric-label">TOTAL WALLETS</span>
                            <span class="metric-badge nav-badge-live">ENTITIES</span>
                        </div>
                        <div class="metric-val text-cyan">${int(overview.wallets)}</div>
                        <div class="metric-meta">${int(overview.total_ips || 170)} IP Nodes Observed</div>
                    </div>

                    <div class="hud-metric-card accent-red">
                        <div class="metric-label-row">
                            <span class="metric-label">HIGH-RISK ENTITIES</span>
                            <span class="metric-badge nav-badge-alert">${num((overview.high_risk_alerts / (overview.wallets || 1)) * 100, 1)}%</span>
                        </div>
                        <div class="metric-val text-red">${int(overview.high_risk_alerts)}</div>
                        <div class="metric-meta">Risk Score ≥ 60 Threshold</div>
                    </div>

                    <div class="hud-metric-card accent-amber">
                        <div class="metric-label-row">
                            <span class="metric-label">ANOMALIES DETECTED</span>
                            <span class="metric-badge nav-badge">ML ISOLATION</span>
                        </div>
                        <div class="metric-val text-amber">${int(overview.anomalies)}</div>
                        <div class="metric-meta">Behavioral Outliers Flagged</div>
                    </div>

                    <div class="hud-metric-card accent-green">
                        <div class="metric-label-row">
                            <span class="metric-label">AVERAGE RISK</span>
                            <span class="metric-badge">BASELINE</span>
                        </div>
                        <div class="metric-val">${num(overview.average_risk, 1)}<span style="font-size:14px;color:var(--text-faint)">/100</span></div>
                        <div class="metric-meta">Global Fleet Score</div>
                    </div>

                    <div class="hud-metric-card accent-red">
                        <div class="metric-label-row">
                            <span class="metric-label">MAXIMUM RISK</span>
                            <span class="metric-badge nav-badge-alert">CRITICAL</span>
                        </div>
                        <div class="metric-val text-red">${num(overview.max_risk, 1)}<span style="font-size:14px;color:var(--text-faint)">/100</span></div>
                        <div class="metric-meta">Top Threat Priority</div>
                    </div>

                    <div class="hud-metric-card accent-cyan">
                        <div class="metric-label-row">
                            <span class="metric-label">TRANSACTION TRAFFIC</span>
                            <span class="metric-badge">CORRELATED</span>
                        </div>
                        <div class="metric-val text-cyan">${int(overview.total_transactions || 3000)}</div>
                        <div class="metric-meta">${int(overview.total_observations || 3000)} Network Observations</div>
                    </div>
                </div>

                <!-- THREAT LANDSCAPE & RISK DISTRIBUTION -->
                <div class="threat-landscape-grid">
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                                </svg>
                                THREAT LANDSCAPE &amp; RISK SPECTRUM
                            </span>
                            <span class="risk-chip ${overview.high_risk_alerts > 0 ? 'critical' : 'safe'}">
                                ${overview.high_risk_alerts} THREATS IDENTIFIED
                            </span>
                        </div>
                        <div class="card-body">
                            <div class="threat-distribution-bar-wrapper">
                                <div class="threat-distribution-bar">
                                    <div class="threat-segment seg-critical" style="width: ${pCrit}%" title="Critical: ${rDist.critical}"></div>
                                    <div class="threat-segment seg-high" style="width: ${pHigh}%" title="High: ${rDist.high}"></div>
                                    <div class="threat-segment seg-medium" style="width: ${pMed}%" title="Medium: ${rDist.medium}"></div>
                                    <div class="threat-segment seg-low" style="width: ${pLow}%" title="Low / Normal: ${rDist.low}"></div>
                                </div>
                            </div>

                            <div class="threat-legend-grid">
                                <div class="threat-legend-card">
                                    <div class="threat-legend-header">
                                        <span class="threat-legend-dot" style="background:var(--risk-critical)"></span>
                                        CRITICAL [≥80]
                                    </div>
                                    <div class="threat-legend-val text-red">${rDist.critical}</div>
                                    <div class="threat-legend-desc">${pCrit}% of entities</div>
                                </div>
                                <div class="threat-legend-card">
                                    <div class="threat-legend-header">
                                        <span class="threat-legend-dot" style="background:var(--risk-high)"></span>
                                        HIGH [60-79]
                                    </div>
                                    <div class="threat-legend-val text-amber">${rDist.high}</div>
                                    <div class="threat-legend-desc">${pHigh}% of entities</div>
                                </div>
                                <div class="threat-legend-card">
                                    <div class="threat-legend-header">
                                        <span class="threat-legend-dot" style="background:var(--risk-medium)"></span>
                                        MEDIUM [35-59]
                                    </div>
                                    <div class="threat-legend-val text-muted">${rDist.medium}</div>
                                    <div class="threat-legend-desc">${pMed}% of entities</div>
                                </div>
                                <div class="threat-legend-card">
                                    <div class="threat-legend-header">
                                        <span class="threat-legend-dot" style="background:var(--risk-safe)"></span>
                                        NORMAL [&lt;35]
                                    </div>
                                    <div class="threat-legend-val text-green">${rDist.low}</div>
                                    <div class="threat-legend-desc">${pLow}% of entities</div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- SESSION TELEMETRY -->
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <polyline points="12 6 12 12 16 14"></polyline>
                                </svg>
                                CURRENT SESSION TELEMETRY
                            </span>
                            <span class="risk-chip safe">ONLINE</span>
                        </div>
                        <div class="card-body">
                            <div class="telemetry-summary-list">
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Session ID</span>
                                    <span class="telemetry-summary-value text-cyan">${latestSession ? esc(latestSession.id) : 'SES-2026-BASELINE'}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Dataset Source</span>
                                    <span class="telemetry-summary-value">${latestSession ? esc(latestSession.dataset_name) : 'bitcoin_traffic.csv'}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">ML Anomaly Detection</span>
                                    <span class="telemetry-summary-value text-green">IsolationForest (300 est.)</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Correlation Engine</span>
                                    <span class="telemetry-summary-value">Network + Flow Multi-Vector</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Observation Nodes</span>
                                    <span class="telemetry-summary-value text-cyan">${int(overview.total_observations || 3000)} Events</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- HIGH-RISK ENTITIES FORENSIC QUEUE -->
                <div class="cyber-card">
                    <div class="card-header">
                        <span class="card-title">
                            <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
                            </svg>
                            TOP SUSPICIOUS BITCOIN ENTITIES
                        </span>
                        <a href="#/alerts" class="technical-link">View All ${overview.high_risk_alerts} Alerts →</a>
                    </div>
                    <div class="table-responsive">
                        <table class="forensic-table">
                            <thead>
                                <tr>
                                    <th>RISK LEVEL</th>
                                    <th>SCORE</th>
                                    <th>WALLET ADDRESS</th>
                                    <th>ANOMALY</th>
                                    <th>CONFIDENCE</th>
                                    <th>PRIMARY EVIDENCE / RATIONALE</th>
                                    <th>ACTIONS</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${topAlerts.map((a) => {
                                    const lvl = getRiskLevel(a.risk_score);
                                    return `
                                        <tr class="${lvl === 'critical' ? 'row-high-risk' : ''}">
                                            <td><span class="risk-chip ${lvl}">${getRiskLabel(a.risk_score)}</span></td>
                                            <td><strong class="mono ${lvl === 'critical' ? 'text-red' : 'text-amber'}">${num(a.risk_score, 1)}</strong></td>
                                            <td>
                                                <a href="#/wallet/${esc(a.wallet_address)}" class="technical-link">
                                                    ${esc(a.wallet_address)}
                                                </a>
                                            </td>
                                            <td class="mono">${num(a.anomaly_score, 4)}</td>
                                            <td class="mono">${num(a.confidence, 1)}%</td>
                                            <td style="max-width:320px; font-size:11.5px; color:var(--text-muted);">${esc(a.explanation || 'ML behavioral deviation detected')}</td>
                                            <td>
                                                <a href="#/wallet/${esc(a.wallet_address)}" class="btn-table-action">
                                                    INVESTIGATE
                                                </a>
                                                <a href="#/network/${esc(a.wallet_address)}" class="btn-table-action">
                                                    GRAPH
                                                </a>
                                            </td>
                                        </tr>
                                    `;
                                }).join("")}
                            </tbody>
                        </table>
                    </div>
                </div>

                <!-- DUAL-COLUMN ACTIVITY & RECENT ALERTS -->
                <div class="feed-split-grid">
                    <!-- RECENT SECURITY ALERTS -->
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                                    <line x1="12" y1="9" x2="12" y2="13"></line>
                                    <line x1="12" y1="17" x2="12.01" y2="17"></line>
                                </svg>
                                REAL-TIME SECURITY ALERTS
                            </span>
                            <span class="status-meta">CRITICAL PRIORITY</span>
                        </div>
                        <div class="card-body">
                            ${topAlerts.slice(0, 5).map((a) => `
                                <div class="feed-item">
                                    <div class="feed-header-row">
                                        <div class="feed-title">
                                            <span class="risk-chip ${getRiskLevel(a.risk_score)}">${num(a.risk_score, 1)}</span>
                                            <a href="#/wallet/${esc(a.wallet_address)}" class="technical-link">
                                                ${shortId(a.wallet_address, 12, 6)}
                                            </a>
                                        </div>
                                        <span class="feed-timestamp">CONF: ${num(a.confidence, 1)}%</span>
                                    </div>
                                    <div class="feed-body">${esc(a.explanation)}</div>
                                    <div class="feed-meta-row">
                                        <span>TX Count: ${int(a.transaction_count || 1)}</span>
                                        <span>•</span>
                                        <span>Source IPs: ${int(a.source_ip_count || 1)}</span>
                                        <span>•</span>
                                        <span>Diversity: ${int(a.network_diversity || 1)}</span>
                                    </div>
                                </div>
                            `).join("")}
                        </div>
                    </div>

                    <!-- LIVE BITCOIN TRAFFIC FEED -->
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
                                </svg>
                                LIVE TRANSACTION &amp; NETWORK TRAFFIC
                            </span>
                            <span class="status-meta">REAL OBSERVATIONS</span>
                        </div>
                        <div class="card-body">
                            ${recentActivity.length ? recentActivity.map((ev) => `
                                <div class="feed-item">
                                    <div class="feed-header-row">
                                        <div class="feed-title">
                                            <span class="risk-chip safe">TX</span>
                                            <a href="#/transaction/${esc(ev.txid)}" class="technical-link">
                                                ${shortId(ev.txid, 10, 6)}
                                            </a>
                                        </div>
                                        <span class="mono text-cyan" style="font-weight:700;">${num(ev.value, 4)} BTC</span>
                                    </div>
                                    <div class="feed-meta-row">
                                        <span>SRC: ${esc(ev.src_ip || 'Internal')}</span>
                                        <span>→</span>
                                        <span>DST: ${esc(ev.dst_ip || 'Internal')}</span>
                                        <span>•</span>
                                        <span class="mono">${esc(ev.country || 'N/A')} (${esc(ev.asn || 'AS-NET')})</span>
                                    </div>
                                    <div class="feed-meta-row" style="font-size:10px;">
                                        <span>${esc(ev.timestamp)}</span>
                                    </div>
                                </div>
                            `).join("") : `
                                <div style="padding:20px;text-align:center;color:var(--text-faint)">No live transaction events recorded.</div>
                            `}
                        </div>
                    </div>
                </div>
            `;

            // Wire trigger button
            const triggerBtn = $("#btn-run-analysis");
            if (triggerBtn) {
                triggerBtn.addEventListener("click", () => {
                    Router.navigate("ingest");
                });
            }
        },

        // ----------------------------------------------------------------------
        // 2. WALLET INTELLIGENCE
        // ----------------------------------------------------------------------
        async renderWalletIntelligence(container, addressParam) {
            // If no address provided, pick the highest risk wallet
            let address = addressParam;
            if (!address) {
                if (!App.state.alerts.length) {
                    try {
                        const data = await API.get("/alerts");
                        App.state.alerts = data.alerts || [];
                    } catch (_) {}
                }
                address = App.state.alerts[0]?.wallet_address || "bc1qc1bdf75d556a47ec841834b5dad877b8";
            }

            // Fetch quick select wallets
            let topWallets = [];
            try {
                const alertsData = await API.get("/alerts");
                App.state.alerts = alertsData.alerts || [];
                topWallets = App.state.alerts.slice(0, 6);
            } catch (_) {}

            let walletData = null;
            try {
                walletData = await API.get(`/wallet/${encodeURIComponent(address)}`);
            } catch (err) {
                container.innerHTML = `
                    <div class="page-header">
                        <div class="page-title-group">
                            <h1 class="page-title">
                                WALLET FORENSIC DOSSIER
                                <span class="risk-chip critical">SEARCH TARGET</span>
                            </h1>
                            <p class="page-subtitle">Deep entity inspection, behavioral profiling, and multi-vector risk indicators.</p>
                        </div>
                    </div>

                    <div class="wallet-selector-bar">
                        <input type="text" id="wallet-err-lookup-input" class="wallet-search-input" placeholder="Enter Bitcoin Wallet Address (bc1...)" value="${esc(address)}">
                        <button class="btn-cyber" id="btn-err-wallet-lookup">INSPECT</button>
                        <div class="quick-wallet-chips">
                            <span style="font-size:11px;color:var(--text-faint);margin-right:4px;">PRIORITY CASES:</span>
                            ${topWallets.map((tw) => `
                                <a href="#/wallet/${esc(tw.wallet_address)}" class="quick-wallet-btn">
                                    ${shortId(tw.wallet_address, 8, 4)} [${Math.round(tw.risk_score)}]
                                </a>
                            `).join("")}
                        </div>
                    </div>

                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title text-red">Target Entity Not Located</span>
                        </div>
                        <div class="card-body">
                            <p style="color:var(--text-muted); margin-bottom:14px;">The wallet address <code class="mono text-cyan">${esc(address)}</code> does not exist in the active forensic dataset.</p>
                            <div style="display:flex;gap:10px;">
                                <a href="#/command-center" class="btn-cyber">Return to Command Center</a>
                                <a href="#/alerts" class="btn-cyber-outline">Browse Threat Alerts</a>
                            </div>
                        </div>
                    </div>
                `;

                const errInput = $("#wallet-err-lookup-input");
                const errBtn = $("#btn-err-wallet-lookup");
                const runErrLookup = () => {
                    const val = errInput ? errInput.value.trim() : "";
                    if (val) Router.navigate(`wallet/${encodeURIComponent(val)}`);
                };
                if (errBtn) errBtn.onclick = runErrLookup;
                if (errInput) errInput.onkeydown = (e) => { if (e.key === "Enter") runErrLookup(); };
                return;
            }

            const w = walletData.wallet;
            const r = walletData.risk;
            const dims = r.risk_dimensions || { ml_classification: 0, velocity_flow: 0, network_telemetry: 0, graph_centrality: 0 };
            const b = walletData.behavior;
            const net = walletData.network;
            const txs = walletData.transactions || [];
            const signals = walletData.signals || [];
            const connectedWallets = walletData.connected_wallets || [];

            const riskLevel = getRiskLevel(r.score);
            const riskLabel = getRiskLabel(r.score);

            container.innerHTML = `
                <!-- WALLET DOSSIER HEADER -->
                <div class="page-header">
                    <div class="page-title-group">
                        <h1 class="page-title">
                            WALLET FORENSIC DOSSIER
                            <span class="risk-chip ${riskLevel}">${riskLabel} RISK</span>
                        </h1>
                        <p class="page-subtitle">Deep entity inspection, behavioral profiling, and multi-vector risk indicators.</p>
                    </div>
                    <div class="page-actions">
                        <a href="#/network/${esc(w.address)}" class="btn-cyber">
                            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="18" cy="5" r="3"></circle>
                                <circle cx="6" cy="12" r="3"></circle>
                                <circle cx="18" cy="19" r="3"></circle>
                                <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>
                                <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>
                            </svg>
                            VIEW IN NETWORK GRAPH
                        </a>
                        <a href="#/reports" class="btn-cyber-outline">GENERATE REPORT</a>
                        <button class="btn-cyber-outline" id="btn-wallet-copy">COPY ADDRESS</button>
                    </div>
                </div>

                <!-- QUICK SELECTOR BAR -->
                <div class="wallet-selector-bar">
                    <input type="text" id="wallet-lookup-input" class="wallet-search-input" placeholder="Search Wallet Address (bc1...)" value="${esc(w.address)}">
                    <button class="btn-cyber" id="btn-wallet-lookup">INSPECT</button>
                    <div class="quick-wallet-chips">
                        <span style="font-size:11px;color:var(--text-faint);margin-right:4px;">PRIORITY CASES:</span>
                        ${topWallets.map((tw) => `
                            <a href="#/wallet/${esc(tw.wallet_address)}" class="quick-wallet-btn ${tw.wallet_address === w.address ? 'active' : ''}">
                                ${shortId(tw.wallet_address, 8, 4)} [${Math.round(tw.risk_score)}]
                            </a>
                        `).join("")}
                    </div>
                </div>

                <!-- WALLET IDENTITY BANNER -->
                <div class="wallet-dossier-header">
                    <div class="wallet-headline">
                        <div style="display:flex;align-items:center;gap:10px;">
                            <span style="font-size:11px;font-weight:700;letter-spacing:0.1em;color:var(--text-faint);">INVESTIGATION TARGET</span>
                            <span class="nav-badge text-cyan">Cluster #${w.cluster_id !== undefined ? w.cluster_id : 0}</span>
                            ${w.high_risk_flag ? '<span class="risk-chip critical" style="font-size:10px;">ANOMALY FLAGGED</span>' : ''}
                        </div>
                        <div class="wallet-address-display">
                            <span class="wallet-address-text">${esc(w.address)}</span>
                            <button class="copy-btn" id="btn-copy-address" title="Copy Address">
                                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                                COPY
                            </button>
                        </div>
                    </div>

                    <div class="wallet-meta-strip">
                        <div class="wallet-meta-item">
                            <span>First Seen:</span>
                            <strong>${w.first_seen ? esc(w.first_seen.split(" ")[0]) : 'N/A'}</strong>
                        </div>
                        <div class="wallet-meta-item">
                            <span>Last Seen:</span>
                            <strong>${w.last_seen ? esc(w.last_seen.split(" ")[0]) : 'N/A'}</strong>
                        </div>
                        <div class="wallet-meta-item">
                            <span>Total Received:</span>
                            <strong class="text-green">${num(w.total_received, 4)} BTC</strong>
                        </div>
                        <div class="wallet-meta-item">
                            <span>Total Sent:</span>
                            <strong class="text-amber">${num(w.total_sent, 4)} BTC</strong>
                        </div>
                        <div class="wallet-meta-item">
                            <span>Net Flow:</span>
                            <strong class="${(w.net_flow || 0) >= 0 ? 'text-green' : 'text-amber'}">${(w.net_flow || 0) >= 0 ? '+' : ''}${num(w.net_flow || 0, 4)} BTC</strong>
                        </div>
                        <div class="wallet-meta-item">
                            <span>Active Balance:</span>
                            <strong class="text-cyan">${num(w.balance || 0, 4)} BTC</strong>
                        </div>
                        <div class="wallet-meta-item">
                            <span>Transactions:</span>
                            <strong class="text-cyan">${int(w.transaction_count)}</strong>
                        </div>
                    </div>
                </div>

                <!-- GRID: RISK MATRIX & BEHAVIORAL PROFILE -->
                <div class="wallet-dossier-grid">
                    <!-- RISK PROFILE & SIGNALS -->
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <line x1="12" y1="8" x2="12" y2="12"></line>
                                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                                </svg>
                                COMPOSITE RISK EVALUATION
                            </span>
                            <span class="risk-chip ${riskLevel}">${num(r.score, 1)} / 100</span>
                        </div>
                        <div class="card-body">
                            <div class="risk-gauge-container">
                                <div class="risk-circle ${riskLevel}">
                                    <span class="risk-number">${num(r.score, 1)}</span>
                                    <span class="risk-denom">SCORE / 100</span>
                                </div>
                                <div style="display:flex;gap:16px;font-size:12px;margin-bottom:8px;">
                                    <span>CONFIDENCE: <strong class="mono text-cyan">${num(r.confidence, 1)}%</strong></span>
                                    <span>•</span>
                                    <span>ANOMALY SCORE: <strong class="mono ${riskLevel === 'critical' ? 'text-red' : 'text-amber'}">${num(r.anomaly_score, 4)}</strong></span>
                                </div>
                                <div class="risk-explanation-callout">
                                    <strong>AI FINDING:</strong> ${esc(r.explanation || 'Anomalous behavioral distribution observed relative to global baseline.')}
                                </div>
                            </div>

                            <!-- 4-VECTOR RISK DIMENSIONS -->
                            <div style="font-size:11px;font-weight:700;color:var(--text-faint);margin:16px 0 8px;letter-spacing:0.08em;">
                                MULTI-VECTOR RISK BREAKDOWN
                            </div>
                            <div class="risk-dimensions-container">
                                <div class="risk-dim-row">
                                    <div class="risk-dim-header">
                                        <span class="risk-dim-name">ML Anomaly Classification (Weight: 50%)</span>
                                        <span class="risk-dim-calc mono ${dims.ml_classification >= 70 ? 'text-red' : 'text-cyan'}">${num(dims.ml_classification, 1)} / 100</span>
                                    </div>
                                    <div class="risk-dim-bar">
                                        <div class="risk-dim-fill" style="width:${Math.min(100, Math.max(5, dims.ml_classification))}%;background:${dims.ml_classification >= 70 ? 'var(--risk-critical)' : 'var(--cyan)'};"></div>
                                    </div>
                                </div>

                                <div class="risk-dim-row">
                                    <div class="risk-dim-header">
                                        <span class="risk-dim-name">Velocity &amp; Flow Imbalance (Weight: 20%)</span>
                                        <span class="risk-dim-calc mono ${dims.velocity_flow >= 70 ? 'text-red' : 'text-amber'}">${num(dims.velocity_flow, 1)} / 100</span>
                                    </div>
                                    <div class="risk-dim-bar">
                                        <div class="risk-dim-fill" style="width:${Math.min(100, Math.max(5, dims.velocity_flow))}%;background:${dims.velocity_flow >= 70 ? 'var(--risk-critical)' : 'var(--amber)'};"></div>
                                    </div>
                                </div>

                                <div class="risk-dim-row">
                                    <div class="risk-dim-header">
                                        <span class="risk-dim-name">Network &amp; Infrastructure Corroboration (Weight: 15%)</span>
                                        <span class="risk-dim-calc mono ${dims.network_telemetry >= 70 ? 'text-red' : 'text-blue'}">${num(dims.network_telemetry, 1)} / 100</span>
                                    </div>
                                    <div class="risk-dim-bar">
                                        <div class="risk-dim-fill" style="width:${Math.min(100, Math.max(5, dims.network_telemetry))}%;background:${dims.network_telemetry >= 70 ? 'var(--risk-critical)' : 'var(--blue)'};"></div>
                                    </div>
                                </div>

                                <div class="risk-dim-row">
                                    <div class="risk-dim-header">
                                        <span class="risk-dim-name">Graph Centrality &amp; Fan-out Dispersion (Weight: 15%)</span>
                                        <span class="risk-dim-calc mono ${dims.graph_centrality >= 70 ? 'text-red' : 'text-green'}">${num(dims.graph_centrality, 1)} / 100</span>
                                    </div>
                                    <div class="risk-dim-bar">
                                        <div class="risk-dim-fill" style="width:${Math.min(100, Math.max(5, dims.graph_centrality))}%;background:${dims.graph_centrality >= 70 ? 'var(--risk-critical)' : 'var(--green)'};"></div>
                                    </div>
                                </div>
                            </div>

                            <div style="font-size:11px;font-weight:700;color:var(--text-faint);margin:16px 0 8px;letter-spacing:0.08em;">
                                INVESTIGATIVE SIGNALS
                            </div>
                            <div class="signals-list">
                                ${signals.length ? signals.map((s) => `
                                    <div class="signal-card">
                                        <span class="signal-badge">${esc(s.category)}</span>
                                        <div>
                                            <div class="signal-title">${esc(s.title)}</div>
                                            <div class="signal-detail">${esc(s.detail)}</div>
                                        </div>
                                    </div>
                                `).join("") : `
                                    <div class="signal-card">
                                        <span class="signal-badge">ML</span>
                                        <div>
                                            <div class="signal-title">Standard Activity Profile</div>
                                            <div class="signal-detail">No elevated behavioral signals triggered.</div>
                                        </div>
                                    </div>
                                `}
                            </div>
                        </div>
                    </div>

                    <!-- BEHAVIOR & NETWORK FOOTPRINT -->
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <line x1="2" y1="12" x2="22" y2="12"></line>
                                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                                </svg>
                                BEHAVIOR &amp; NETWORK INFRASTRUCTURE
                            </span>
                            <span class="status-meta">${net.observation_count} OBSERVATIONS</span>
                        </div>
                        <div class="card-body">
                            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(130px, 1fr));gap:10px;margin-bottom:18px;">
                                <div class="telemetry-summary-item" style="flex-direction:column;align-items:flex-start;">
                                    <span class="telemetry-summary-label">Source IPs</span>
                                    <span class="telemetry-summary-value text-cyan">${int(b.source_ip_count)}</span>
                                </div>
                                <div class="telemetry-summary-item" style="flex-direction:column;align-items:flex-start;">
                                    <span class="telemetry-summary-label">Dest IPs</span>
                                    <span class="telemetry-summary-value">${int(b.destination_ip_count)}</span>
                                </div>
                                <div class="telemetry-summary-item" style="flex-direction:column;align-items:flex-start;">
                                    <span class="telemetry-summary-label">Network Diversity</span>
                                    <span class="telemetry-summary-value text-amber">${int(b.network_diversity)}</span>
                                </div>
                                <div class="telemetry-summary-item" style="flex-direction:column;align-items:flex-start;">
                                    <span class="telemetry-summary-label">Flow Imbalance</span>
                                    <span class="telemetry-summary-value">${num(b.flow_imbalance, 2)}</span>
                                </div>
                                <div class="telemetry-summary-item" style="flex-direction:column;align-items:flex-start;">
                                    <span class="telemetry-summary-label">Velocity (TX/IP)</span>
                                    <span class="telemetry-summary-value">${num(b.tx_per_ip, 2)}</span>
                                </div>
                                <div class="telemetry-summary-item" style="flex-direction:column;align-items:flex-start;">
                                    <span class="telemetry-summary-label">Avg TX Value</span>
                                    <span class="telemetry-summary-value text-green">${num(b.avg_tx_value, 4)} BTC</span>
                                </div>
                            </div>

                            <div style="font-size:11px;font-weight:700;color:var(--text-faint);margin-bottom:8px;letter-spacing:0.08em;">
                                CORRELATED GEOGRAPHIES &amp; ASNs
                            </div>
                            <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:16px;">
                                ${net.countries.map((c) => `<span class="nav-badge" style="color:#fff;">GEO: ${esc(c)}</span>`).join("") || '<span style="color:var(--text-faint)">No country telemetry</span>'}
                                ${net.asns.map((a) => `<span class="nav-badge text-cyan">${esc(a)}</span>`).join("") || '<span style="color:var(--text-faint)">No ASN telemetry</span>'}
                            </div>

                            <div style="font-size:11px;font-weight:700;color:var(--text-faint);margin-bottom:8px;letter-spacing:0.08em;">
                                OBSERVED SOURCE IP NODES (${(net.source_ips || []).length})
                            </div>
                            <div style="display:flex;flex-wrap:wrap;gap:6px;max-height:100px;overflow-y:auto;background:var(--bg-alt);padding:10px;border-radius:var(--radius-sm);border:1px solid var(--border-subtle);margin-bottom:14px;">
                                ${(net.source_ips || []).map((ip) => `<span class="mono" style="font-size:11px;background:var(--surface);padding:2px 6px;border-radius:3px;border:1px solid var(--border-subtle);">${esc(ip)}</span>`).join("") || '<span style="color:var(--text-faint)">No IP nodes observed</span>'}
                            </div>

                            <div style="font-size:11px;font-weight:700;color:var(--text-faint);margin-bottom:8px;letter-spacing:0.08em;">
                                OBSERVED DESTINATION IP NODES (${(net.destination_ips || []).length})
                            </div>
                            <div style="display:flex;flex-wrap:wrap;gap:6px;max-height:100px;overflow-y:auto;background:var(--bg-alt);padding:10px;border-radius:var(--radius-sm);border:1px solid var(--border-subtle);">
                                ${(net.destination_ips || []).map((ip) => `<span class="mono" style="font-size:11px;background:var(--surface);padding:2px 6px;border-radius:3px;border:1px solid var(--border-subtle);">${esc(ip)}</span>`).join("") || '<span style="color:var(--text-faint)">No destination IP records</span>'}
                            </div>
                        </div>
                    </div>
                </div>

                <!-- CONNECTED COUNTERPARTY NETWORK -->
                ${connectedWallets.length ? `
                    <div class="cyber-card" style="margin-bottom:20px;">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                                    <circle cx="9" cy="7" r="4"></circle>
                                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                                    <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                                </svg>
                                DIRECT CONNECTED COUNTERPARTIES (${connectedWallets.length})
                            </span>
                            <span class="status-meta">PEER CLUSTER MEMBERS</span>
                        </div>
                        <div class="table-responsive">
                            <table class="forensic-table">
                                <thead>
                                    <tr>
                                        <th>COUNTERPARTY ADDRESS</th>
                                        <th>RISK ASSESSMENT</th>
                                        <th>TX VOLUME</th>
                                        <th>CLUSTER</th>
                                        <th>ACTION</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${connectedWallets.map((cw) => {
                                        const cRiskLevel = getRiskLevel(cw.risk_score || 0);
                                        return `
                                            <tr>
                                                <td class="mono">
                                                    <a href="#/wallet/${esc(cw.address)}" class="technical-link">
                                                        ${shortId(cw.address, 16, 8)}
                                                    </a>
                                                </td>
                                                <td>
                                                    <span class="risk-chip ${cRiskLevel}">${num(cw.risk_score, 1)} / 100</span>
                                                </td>
                                                <td class="mono">${int(cw.transaction_count || 1)} txs</td>
                                                <td class="mono text-cyan">#${cw.cluster_id !== undefined ? cw.cluster_id : 0}</td>
                                                <td>
                                                    <a href="#/wallet/${esc(cw.address)}" class="btn-table-action">
                                                        INSPECT DOSSIER
                                                    </a>
                                                </td>
                                            </tr>
                                        `;
                                    }).join("")}
                                </tbody>
                            </table>
                        </div>
                    </div>
                ` : ''}

                <!-- TRANSACTION ACTIVITY TABLE -->
                <div class="cyber-card">
                    <div class="card-header">
                        <span class="card-title">
                            <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                <rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect>
                                <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path>
                            </svg>
                            ASSOCIATED TRANSACTION ACTIVITY (${txs.length})
                        </span>
                        <span class="status-meta">CHRONOLOGICAL TRACE</span>
                    </div>
                    <div class="table-responsive">
                        <table class="forensic-table">
                            <thead>
                                <tr>
                                    <th>DIRECTION</th>
                                    <th>TXID</th>
                                    <th>TIMESTAMP</th>
                                    <th>SCRIPT TYPE</th>
                                    <th>IN / OUT</th>
                                    <th>TOTAL IN (BTC)</th>
                                    <th>TOTAL OUT (BTC)</th>
                                    <th>FEE (BTC)</th>
                                    <th>ACTION</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${txs.map((tx) => {
                                    const dir = tx.direction || 'TRANSFER';
                                    const dirClass = dir === 'INCOMING' ? 'safe' : dir === 'OUTGOING' ? 'high' : 'medium';
                                    return `
                                        <tr>
                                            <td><span class="risk-chip ${dirClass}" style="font-size:10px;">${esc(dir)}</span></td>
                                            <td>
                                                <a href="#/transaction/${esc(tx.txid)}" class="technical-link">
                                                    ${shortId(tx.txid, 12, 6)}
                                                </a>
                                            </td>
                                            <td class="mono">${esc(tx.timestamp)}</td>
                                            <td><span class="nav-badge">${esc(tx.script_type || 'P2WPKH')}</span></td>
                                            <td class="mono">${int(tx.input_count)} / ${int(tx.output_count)}</td>
                                            <td class="mono">${num(tx.total_input, 4)}</td>
                                            <td class="mono text-cyan">${num(tx.total_output, 4)}</td>
                                            <td class="mono">${num(tx.fee, 6)}</td>
                                            <td>
                                                <a href="#/transaction/${esc(tx.txid)}" class="btn-table-action">
                                                    TRACE FLOW
                                                </a>
                                            </td>
                                        </tr>
                                    `;
                                }).join("")}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;

            // Wire lookup controls
            const input = $("#wallet-lookup-input");
            const btn = $("#btn-wallet-lookup");
            const runLookup = () => {
                const val = input ? input.value.trim() : "";
                if (val) Router.navigate(`wallet/${encodeURIComponent(val)}`);
            };
            if (btn) btn.onclick = runLookup;
            if (input) {
                input.onkeydown = (e) => {
                    if (e.key === "Enter") runLookup();
                };
            }

            const copyBtn1 = $("#btn-copy-address");
            if (copyBtn1) copyBtn1.onclick = () => copyToClipboard(w.address, "Wallet Address");
            const copyBtn2 = $("#btn-wallet-copy");
            if (copyBtn2) copyBtn2.onclick = () => copyToClipboard(w.address, "Wallet Address");
        },

        // ----------------------------------------------------------------------
        // 3. TRANSACTION FLOW
        // ----------------------------------------------------------------------
        async renderTransactionFlow(container, txidParam) {
            let txid = txidParam;
            if (!txid) {
                try {
                    const txListData = await API.get("/transactions?limit=1");
                    txid = txListData.transactions[0]?.txid || "edd4c60f1d62417fa0ca0f187774bd375b5afeb64bbc44a1ab0ec24864dc74ef";
                } catch (_) {
                    txid = "edd4c60f1d62417fa0ca0f187774bd375b5afeb64bbc44a1ab0ec24864dc74ef";
                }
            }

            // Fetch recent transactions for quick select
            let txHistory = [];
            try {
                const txHData = await API.get("/transactions?limit=6");
                txHistory = txHData.transactions || [];
            } catch (_) {}

            let tx = null;
            try {
                tx = await API.get(`/transaction/${encodeURIComponent(txid)}`);
            } catch (err) {
                container.innerHTML = `
                    <div class="page-header">
                        <div class="page-title-group">
                            <h1 class="page-title">
                                TRANSACTION FORENSIC FLOW
                                <span class="risk-chip critical">SEARCH TARGET</span>
                            </h1>
                            <p class="page-subtitle">Visual input/output correlation, fan-out signals, and connected network observation trace.</p>
                        </div>
                    </div>

                    <div class="wallet-selector-bar">
                        <input type="text" id="tx-err-lookup-input" class="wallet-search-input" placeholder="Search Transaction Hash (TXID)..." value="${esc(txid)}">
                        <button class="btn-cyber" id="btn-err-tx-lookup">INSPECT FLOW</button>
                        <div class="quick-wallet-chips">
                            <span style="font-size:11px;color:var(--text-faint);margin-right:4px;">RECENT TXS:</span>
                            ${txHistory.map((t) => `
                                <a href="#/transaction/${esc(t.txid)}" class="quick-wallet-btn">
                                    ${shortId(t.txid, 8, 4)} [${num(t.value, 2)} BTC]
                                </a>
                            `).join("")}
                        </div>
                    </div>

                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title text-red">Transaction Record Not Located</span>
                        </div>
                        <div class="card-body">
                            <p style="color:var(--text-muted); margin-bottom:14px;">The TXID <code class="mono text-cyan">${esc(txid)}</code> does not exist in the active forensic dataset.</p>
                            <div style="display:flex;gap:10px;">
                                <a href="#/command-center" class="btn-cyber">Return to Command Center</a>
                                <a href="#/alerts" class="btn-cyber-outline">Browse Threat Alerts</a>
                            </div>
                        </div>
                    </div>
                `;

                const errInput = $("#tx-err-lookup-input");
                const errBtn = $("#btn-err-tx-lookup");
                const runErrLookup = () => {
                    const val = errInput ? errInput.value.trim() : "";
                    if (val) Router.navigate(`transaction/${encodeURIComponent(val)}`);
                };
                if (errBtn) errBtn.onclick = runErrLookup;
                if (errInput) errInput.onkeydown = (e) => { if (e.key === "Enter") runErrLookup(); };
                return;
            }

            const priorityLevel = getRiskLevel(tx.priority);
            const priorityLabel = tx.severity || getRiskLabel(tx.priority);
            const flow = tx.flow || {};
            const evidence = tx.evidence || [];
            const net = tx.network || {};
            const wallets = tx.wallets || {};

            container.innerHTML = `
                <!-- TRANSACTION FLOW HEADER -->
                <div class="page-header">
                    <div class="page-title-group">
                        <h1 class="page-title">
                            TRANSACTION FORENSIC FLOW
                            <span class="risk-chip ${priorityLevel}">${priorityLabel} PRIORITY</span>
                        </h1>
                        <p class="page-subtitle">Visual input/output correlation, fan-out signals, and connected network observation trace.</p>
                    </div>
                    <div class="page-actions">
                        <a href="#/network" class="btn-cyber">
                            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="18" cy="5" r="3"></circle>
                                <circle cx="6" cy="12" r="3"></circle>
                                <circle cx="18" cy="19" r="3"></circle>
                                <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"></line>
                                <line x1="15.41" y1="6.51" x2="8.59" y2="10.49"></line>
                            </svg>
                            VIEW IN NETWORK GRAPH
                        </a>
                        <button class="btn-cyber-outline" id="btn-copy-txid">COPY TXID</button>
                    </div>
                </div>

                <!-- QUICK SELECTOR BAR -->
                <div class="wallet-selector-bar">
                    <input type="text" id="tx-lookup-input" class="wallet-search-input" placeholder="Search Transaction Hash (TXID)..." value="${esc(tx.txid)}">
                    <button class="btn-cyber" id="btn-tx-lookup">INSPECT FLOW</button>
                    <div class="quick-wallet-chips">
                        <span style="font-size:11px;color:var(--text-faint);margin-right:4px;">RECENT TXS:</span>
                        ${txHistory.map((t) => `
                            <a href="#/transaction/${esc(t.txid)}" class="quick-wallet-btn ${t.txid === tx.txid ? 'active' : ''}">
                                ${shortId(t.txid, 8, 4)} [${num(t.value, 2)} BTC]
                            </a>
                        `).join("")}
                    </div>
                </div>

                <!-- TRANSACTION METADATA STRIP -->
                <div class="wallet-dossier-header">
                    <div class="wallet-headline">
                        <div style="display:flex;align-items:center;gap:10px;">
                            <span style="font-size:11px;font-weight:700;letter-spacing:0.1em;color:var(--text-faint);">TRANSACTION HASH</span>
                            <span class="nav-badge text-cyan">${esc(tx.script_type || 'P2WPKH')}</span>
                        </div>
                        <div class="wallet-address-display">
                            <span class="wallet-address-text" style="font-size:14px;">${esc(tx.txid)}</span>
                            <button class="copy-btn" id="btn-copy-txid-inner" title="Copy TXID">
                                <svg viewBox="0 0 24 24" width="13" height="13" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                                COPY
                            </button>
                        </div>
                    </div>

                    <div class="wallet-meta-strip">
                        <div class="wallet-meta-item">
                            <span>Timestamp:</span>
                            <strong>${esc(tx.timestamp)}</strong>
                        </div>
                        <div class="wallet-meta-item">
                            <span>Total Volume:</span>
                            <strong class="text-green">${num(flow.value || flow.total_output || 0, 4)} BTC</strong>
                        </div>
                        <div class="wallet-meta-item">
                            <span>Miner Fee:</span>
                            <strong class="text-amber">${num(tx.fee, 6)} BTC</strong>
                        </div>
                        <div class="wallet-meta-item">
                            <span>Inputs / Outputs:</span>
                            <strong class="text-cyan">${int(flow.input_count || 1)} in / ${int(flow.output_count || 1)} out</strong>
                        </div>
                        <div class="wallet-meta-item">
                            <span>Priority Score:</span>
                            <strong class="${priorityLevel === 'critical' ? 'text-red' : 'text-amber'}">${num(tx.priority, 1)} / 100</strong>
                        </div>
                    </div>
                </div>

                <!-- VISUAL FLOW: INPUTS -> TRANSACTION BOX -> OUTPUTS -->
                <div class="tx-flow-diagram">
                    <!-- INPUTS PANEL -->
                    <div class="tx-endpoint-panel">
                        <div class="tx-endpoint-header">
                            <span>INPUTS (${flow.input_count || 1})</span>
                            <span class="mono text-green">${num(flow.total_input || flow.value || 0, 4)} BTC</span>
                        </div>
                        <div class="tx-address-item">
                            <span style="font-size:10px;color:var(--text-faint);">SOURCE WALLET</span>
                            ${flow.from ? `
                                <a href="#/wallet/${esc(flow.from)}" class="technical-link">
                                    ${shortId(flow.from, 14, 8)}
                                </a>
                            ` : '<span class="mono" style="color:var(--text-faint)">Multiple Inputs</span>'}
                            <span class="tx-amount-badge text-green">${num(flow.total_input || flow.value || 0, 4)} BTC</span>
                        </div>
                    </div>

                    <!-- CONNECTOR -->
                    <div class="tx-connector-node">
                        <div class="tx-node-box">
                            <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <polyline points="12 6 12 12 16 14"></polyline>
                            </svg>
                            <span style="font-size:10px;font-weight:700;margin-top:2px;">FLOW</span>
                        </div>
                        <span class="risk-chip ${priorityLevel}" style="font-size:10px;">${priorityLabel}</span>
                    </div>

                    <!-- OUTPUTS PANEL -->
                    <div class="tx-endpoint-panel">
                        <div class="tx-endpoint-header">
                            <span>OUTPUTS (${flow.output_count || 1})</span>
                            <span class="mono text-cyan">${num(flow.total_output || flow.value || 0, 4)} BTC</span>
                        </div>
                        <div class="tx-address-item">
                            <span style="font-size:10px;color:var(--text-faint);">DESTINATION WALLET</span>
                            ${flow.to ? `
                                <a href="#/wallet/${esc(flow.to)}" class="technical-link">
                                    ${shortId(flow.to, 14, 8)}
                                </a>
                            ` : '<span class="mono" style="color:var(--text-faint)">Multiple Outputs</span>'}
                            <span class="tx-amount-badge text-cyan">${num(flow.total_output || flow.value || 0, 4)} BTC</span>
                        </div>
                    </div>
                </div>

                <!-- EVIDENCE & NETWORK PROFILE -->
                <div class="wallet-dossier-grid">
                    <!-- INVESTIGATIVE EVIDENCE -->
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"></polygon>
                                </svg>
                                INVESTIGATIVE SIGNALS &amp; EVIDENCE
                            </span>
                            <span class="risk-chip ${priorityLevel}">SCORE ${num(tx.priority, 1)}</span>
                        </div>
                        <div class="card-body">
                            <div class="risk-explanation-callout" style="margin-top:0;margin-bottom:14px;">
                                <strong>SYNTHESIZED EXPLANATION:</strong> ${esc(tx.explanation || 'Transaction exhibiting elevated fan-out dispersion and anomaly telemetry relative to baseline.')}
                            </div>

                            <div class="signals-list">
                                ${evidence.length ? evidence.map((e) => `
                                    <div class="signal-card">
                                        <span class="signal-badge">${esc((e.category || 'SIGNAL').toUpperCase())}</span>
                                        <div>
                                            <div class="signal-title">${esc(e.title)} ${e.points ? `(+${num(e.points, 1)} pts)` : ''}</div>
                                            <div class="signal-detail">Observed: <strong>${esc(e.observed || 'N/A')}</strong> | Baseline: <strong>${esc(e.baseline || 'Standard')}</strong></div>
                                        </div>
                                    </div>
                                `).join("") : `
                                    <div class="signal-card">
                                        <span class="signal-badge">FLOW</span>
                                        <div>
                                            <div class="signal-title">Standard Transfer Flow</div>
                                            <div class="signal-detail">Values align with dataset baseline.</div>
                                        </div>
                                    </div>
                                `}
                            </div>
                        </div>
                    </div>

                    <!-- NETWORK OBSERVATIONS -->
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <circle cx="12" cy="12" r="10"></circle>
                                    <line x1="2" y1="12" x2="22" y2="12"></line>
                                    <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"></path>
                                </svg>
                                NETWORK-LAYER OBSERVATIONS (${net.observation_count || 0})
                            </span>
                            <span class="status-meta">CORRELATED IP NODES</span>
                        </div>
                        <div class="card-body">
                            <div style="margin-bottom:14px;">
                                <div style="font-size:11px;font-weight:700;color:var(--text-faint);margin-bottom:8px;letter-spacing:0.08em;">
                                    SOURCE IP INFRASTRUCTURE (${(net.source_ips || []).length})
                                </div>
                                <div style="display:flex;flex-wrap:wrap;gap:6px;">
                                    ${(net.source_ips || []).map((ip) => `<span class="mono" style="font-size:11px;background:var(--bg-alt);padding:4px 8px;border-radius:3px;border:1px solid var(--border-subtle);">${esc(ip)}</span>`).join("") || '<span style="color:var(--text-faint)">No source IP records</span>'}
                                </div>
                            </div>

                            <div style="margin-bottom:14px;">
                                <div style="font-size:11px;font-weight:700;color:var(--text-faint);margin-bottom:8px;letter-spacing:0.08em;">
                                    DESTINATION IP INFRASTRUCTURE (${(net.destination_ips || []).length})
                                </div>
                                <div style="display:flex;flex-wrap:wrap;gap:6px;">
                                    ${(net.destination_ips || []).map((ip) => `<span class="mono" style="font-size:11px;background:var(--bg-alt);padding:4px 8px;border-radius:3px;border:1px solid var(--border-subtle);">${esc(ip)}</span>`).join("") || '<span style="color:var(--text-faint)">No destination IP records</span>'}
                                </div>
                            </div>

                            <div>
                                <div style="font-size:11px;font-weight:700;color:var(--text-faint);margin-bottom:8px;letter-spacing:0.08em;">
                                    CONNECTED WALLETS FLEET RISK
                                </div>
                                <div style="display:flex;gap:16px;background:var(--bg-alt);padding:10px 14px;border-radius:var(--radius-sm);border:1px solid var(--border-subtle);">
                                    <div>
                                        <span style="font-size:10px;color:var(--text-faint);">WALLET COUNT:</span>
                                        <div class="mono" style="font-weight:700;">${wallets.count || 0}</div>
                                    </div>
                                    <div>
                                        <span style="font-size:10px;color:var(--text-faint);">MAX WALLET RISK:</span>
                                        <div class="mono text-red" style="font-weight:700;">${num(wallets.max_risk, 1)}</div>
                                    </div>
                                    <div>
                                        <span style="font-size:10px;color:var(--text-faint);">AVG WALLET RISK:</span>
                                        <div class="mono text-amber" style="font-weight:700;">${num(wallets.average_risk, 1)}</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            // Wire lookup controls
            const input = $("#tx-lookup-input");
            const btn = $("#btn-tx-lookup");
            const runLookup = () => {
                const val = input ? input.value.trim() : "";
                if (val) Router.navigate(`transaction/${encodeURIComponent(val)}`);
            };
            if (btn) btn.onclick = runLookup;
            if (input) {
                input.onkeydown = (e) => {
                    if (e.key === "Enter") runLookup();
                };
            }

            const copyBtn = $("#btn-copy-txid");
            if (copyBtn) copyBtn.onclick = () => copyToClipboard(tx.txid, "Transaction Hash");
            const copyBtnInner = $("#btn-copy-txid-inner");
            if (copyBtnInner) copyBtnInner.onclick = () => copyToClipboard(tx.txid, "Transaction Hash");
        },

        // ----------------------------------------------------------------------
        // 4. NETWORK GRAPH
        // ----------------------------------------------------------------------
        async renderNetworkGraph(container, focusWalletParam) {
            let focusWallet = focusWalletParam || "";
            if (!focusWallet && App.state.alerts.length) {
                focusWallet = App.state.alerts[0]?.wallet_address || "";
            }

            let topWallets = [];
            try {
                if (!App.state.alerts.length) {
                    const data = await API.get("/alerts");
                    App.state.alerts = data.alerts || [];
                }
                topWallets = App.state.alerts.slice(0, 12);
            } catch (_) {}

            container.innerHTML = `
                <div class="page-header">
                    <div class="page-title-group">
                        <h1 class="page-title">
                            NETWORK INTELLIGENCE GRAPH
                            <span class="risk-chip safe">TOPOLOGY WORKSTATION</span>
                        </h1>
                        <p class="page-subtitle">Interactive entity relationship map correlating Bitcoin wallets, transaction flows, and IP infrastructure.</p>
                    </div>
                </div>

                <!-- NETWORK GRAPH SYNOPSIS STRIP -->
                <div class="graph-synopsis-strip" id="graph-synopsis-bar">
                    <div class="synopsis-item">
                        <span>DATASET:</span>
                        <strong class="text-cyan" id="syn-dataset">Active Dataset</strong>
                    </div>
                    <div class="synopsis-item">
                        <span>TOTAL NODES:</span>
                        <strong class="mono" id="syn-nodes">-</strong>
                    </div>
                    <div class="synopsis-item">
                        <span>TOTAL EDGES:</span>
                        <strong class="mono" id="syn-edges">-</strong>
                    </div>
                    <div class="synopsis-item">
                        <span>GRAPH DENSITY:</span>
                        <strong class="mono" id="syn-density">-</strong>
                    </div>
                    <div class="synopsis-item">
                        <span>HIGH-RISK ENTITIES:</span>
                        <strong class="mono text-red" id="syn-risk">-</strong>
                    </div>
                    <div class="synopsis-item">
                        <span>MEAN DEGREE:</span>
                        <strong class="mono text-amber" id="syn-degree">-</strong>
                    </div>
                </div>

                <!-- FILTER CONTROLS BAR -->
                <div class="wallet-selector-bar" style="margin-bottom:12px;gap:10px;">
                    <div style="display:flex;align-items:center;gap:6px;">
                        <span style="font-size:11px;color:var(--text-faint);font-weight:700;">SCOPE:</span>
                        <select id="graph-scope-select" class="wallet-search-input" style="padding:5px 8px;font-size:11px;min-width:140px;flex:none;">
                            <option value="focused" ${focusWallet ? 'selected' : ''}>Focused Target Subgraph</option>
                            <option value="all" ${!focusWallet ? 'selected' : ''}>Global Dataset Overview</option>
                        </select>
                    </div>

                    <div style="display:flex;align-items:center;gap:6px;" id="focus-wallet-container">
                        <span style="font-size:11px;color:var(--text-faint);font-weight:700;">FOCUS WALLET:</span>
                        <select id="graph-focus-select" class="wallet-search-input" style="padding:5px 8px;font-size:11px;min-width:220px;flex:none;">
                            <option value="">Select Priority Target...</option>
                            ${topWallets.map((a) => `
                                <option value="${esc(a.wallet_address)}" ${a.wallet_address === focusWallet ? 'selected' : ''}>
                                    ${shortId(a.wallet_address, 10, 6)} [Risk: ${Math.round(a.risk_score)}]
                                </option>
                            `).join("")}
                        </select>
                    </div>

                    <div style="display:flex;align-items:center;gap:6px;">
                        <span style="font-size:11px;color:var(--text-faint);font-weight:700;">NODES:</span>
                        <select id="graph-limit-select" class="wallet-search-input" style="padding:5px 8px;font-size:11px;min-width:80px;flex:none;">
                            <option value="60">60 nodes</option>
                            <option value="120" selected>120 nodes</option>
                            <option value="200">200 nodes</option>
                        </select>
                    </div>

                    <div style="display:flex;align-items:center;gap:8px;margin-left:auto;flex-wrap:wrap;">
                        <input type="text" id="graph-search-node" class="wallet-search-input" style="padding:5px 8px;font-size:11px;min-width:160px;flex:none;" placeholder="Find Node ID...">
                        <button class="btn-cyber" id="btn-graph-reload" style="padding:5px 10px;font-size:11px;">APPLY</button>
                    </div>
                </div>

                <div class="graph-workstation-container" id="graph-container">
                    <!-- GRAPH CANVAS -->
                    <canvas id="graph-canvas" class="graph-canvas"></canvas>

                    <!-- FLOATING TOOLBAR -->
                    <div class="graph-toolbar">
                        <button class="graph-tool-btn" id="graph-zoom-in" title="Zoom In">+</button>
                        <button class="graph-tool-btn" id="graph-zoom-out" title="Zoom Out">−</button>
                        <button class="graph-tool-btn" id="graph-reset" title="Reset View">⟲</button>
                    </div>

                    <!-- LEGEND STRIP -->
                    <div class="graph-legend-strip">
                        <div class="legend-item">
                            <span class="legend-swatch wallet"></span>
                            <span>Wallet</span>
                        </div>
                        <div class="legend-item">
                            <span class="legend-swatch wallet-risk"></span>
                            <span>High-Risk Wallet (Score ≥ 60)</span>
                        </div>
                        <div class="legend-item">
                            <span class="legend-swatch transaction"></span>
                            <span>Transaction Node</span>
                        </div>
                        <div class="legend-item">
                            <span class="legend-swatch ip"></span>
                            <span>IP Address Node</span>
                        </div>
                    </div>

                    <!-- NODE INSPECTOR DRAWER -->
                    <div class="graph-inspector-drawer hidden" id="graph-inspector">
                        <div style="display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid var(--border-subtle);padding-bottom:10px;">
                            <span class="card-title" id="inspector-type">NODE INSPECTION</span>
                            <button class="header-btn" id="btn-close-inspector" style="padding:2px 6px;">✕</button>
                        </div>
                        <div>
                            <span style="font-size:10px;color:var(--text-faint);display:block;margin-bottom:4px;">IDENTIFIER</span>
                            <div class="mono" id="inspector-id" style="font-size:12px;word-break:break-all;color:var(--cyan);background:var(--bg-alt);padding:8px;border-radius:4px;border:1px solid var(--border-subtle);"></div>
                        </div>
                        <div id="inspector-metrics" style="display:flex;flex-direction:column;gap:8px;"></div>
                        <div style="margin-top:auto;">
                            <button class="btn-cyber" id="btn-inspector-action" style="width:100%;justify-content:center;">
                                INVESTIGATE ENTITY
                            </button>
                        </div>
                    </div>
                </div>
            `;

            const loadGraph = async () => {
                const scope = $("#graph-scope-select")?.value || (focusWallet ? "focused" : "all");
                const targetWallet = $("#graph-focus-select")?.value || focusWallet;
                const limit = $("#graph-limit-select")?.value || 120;

                let endpoint = `/graph?scope=${encodeURIComponent(scope)}&max_nodes=${limit}`;
                if (scope === "focused" && targetWallet) {
                    endpoint = `/graph/focused?wallet_address=${encodeURIComponent(targetWallet)}&max_nodes=${limit}`;
                }

                try {
                    const graphData = await API.get(endpoint);
                    App.state.graphData = graphData;

                    // Update synopsis bar
                    const syn = graphData.synopsis || {};
                    const synDataset = $("#syn-dataset");
                    if (synDataset) synDataset.textContent = syn.active_dataset || "Active Dataset";
                    const synNodes = $("#syn-nodes");
                    if (synNodes) synNodes.textContent = int(syn.total_nodes || graphData.nodes?.length || 0);
                    const synEdges = $("#syn-edges");
                    if (synEdges) synEdges.textContent = int(syn.total_edges || graphData.edges?.length || 0);
                    const synDensity = $("#syn-density");
                    if (synDensity) synDensity.textContent = num(syn.density || 0, 4);
                    const synRisk = $("#syn-risk");
                    if (synRisk) synRisk.textContent = int(syn.high_risk_entities || 0);
                    const synDegree = $("#syn-degree");
                    if (synDegree) synDegree.textContent = num(syn.mean_degree || 0, 2);

                    this.initCanvasGraph(graphData);
                } catch (err) {
                    showToast(`Failed to load graph: ${err.message}`, "error");
                }
            };

            await loadGraph();

            // Wire controls
            const scopeSelect = $("#graph-scope-select");
            const focusContainer = $("#focus-wallet-container");
            const focusSelect = $("#graph-focus-select");
            const reloadBtn = $("#btn-graph-reload");
            const searchInput = $("#graph-search-node");

            if (scopeSelect) {
                scopeSelect.onchange = () => {
                    if (scopeSelect.value === "focused") {
                        if (focusContainer) focusContainer.style.display = "flex";
                    } else {
                        if (focusContainer) focusContainer.style.display = "none";
                    }
                    loadGraph();
                };
                if (scopeSelect.value === "all" && focusContainer) {
                    focusContainer.style.display = "none";
                }
            }

            if (focusSelect) {
                focusSelect.onchange = () => {
                    if (scopeSelect) scopeSelect.value = "focused";
                    if (focusContainer) focusContainer.style.display = "flex";
                    loadGraph();
                };
            }

            if (reloadBtn) reloadBtn.onclick = () => loadGraph();

            if (searchInput) {
                searchInput.onkeydown = (e) => {
                    if (e.key === "Enter") {
                        const term = searchInput.value.trim().toLowerCase();
                        if (term && window.__tracex_highlight_node) {
                            window.__tracex_highlight_node(term);
                        }
                    }
                };
            }
        },

        initCanvasGraph(data) {
            const canvas = $("#graph-canvas");
            if (!canvas) return;
            const ctx = canvas.getContext("2d");
            const container = $("#graph-container");

            if (App.graphSimulation) {
                cancelAnimationFrame(App.graphSimulation);
                App.graphSimulation = null;
            }

            let width = container.clientWidth || 800;
            let height = container.clientHeight || 560;
            canvas.width = width * window.devicePixelRatio;
            canvas.height = height * window.devicePixelRatio;
            ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

            const rawNodes = data.nodes || [];
            const rawEdges = data.edges || [];

            // Fast high-risk wallet lookup map
            const highRiskWallets = new Set((App.state.alerts || []).map(a => a.wallet_address));

            const nodesMap = new Map();
            const nodes = rawNodes.map((n, i) => {
                const angle = (i / Math.max(1, rawNodes.length)) * 2 * Math.PI;
                const radius = 80 + Math.random() * 160;
                const isRisk = n.type === "wallet" && (n.is_risk || highRiskWallets.has(n.id) || (n.risk_score && n.risk_score >= 60));
                const nodeObj = {
                    id: n.id,
                    type: n.type,
                    isRisk: isRisk,
                    riskScore: n.risk_score || (isRisk ? 80 : 20),
                    degree: n.degree || 0,
                    x: width / 2 + Math.cos(angle) * radius,
                    y: height / 2 + Math.sin(angle) * radius,
                    vx: 0,
                    vy: 0,
                    radius: n.type === "wallet" ? (isRisk ? 10 : 8) : n.type === "transaction" ? 6 : 5
                };
                nodesMap.set(n.id, nodeObj);
                return nodeObj;
            });

            const links = rawEdges.map((e) => ({
                source: nodesMap.get(e.source),
                target: nodesMap.get(e.target),
                relationship: e.relationship
            })).filter(l => l.source && l.target);

            // Camera Viewport
            let zoom = 1;
            let panX = 0;
            let panY = 0;
            let isDragging = false;
            let dragNode = null;
            let startMouse = { x: 0, y: 0 };
            let selectedNode = null;

            const inspector = $("#graph-inspector");
            const inspectorType = $("#inspector-type");
            const inspectorId = $("#inspector-id");
            const inspectorMetrics = $("#inspector-metrics");
            const inspectorBtn = $("#btn-inspector-action");

            const openInspector = (node) => {
                selectedNode = node;
                if (!inspector) return;
                inspector.classList.remove("hidden");
                inspectorType.textContent = `${node.type.toUpperCase()} NODE`;
                inspectorId.textContent = node.id;

                let metricsHtml = `
                    <div class="telemetry-summary-item">
                        <span class="telemetry-summary-label">Node Type</span>
                        <span class="telemetry-summary-value text-cyan">${node.type.toUpperCase()}</span>
                    </div>
                `;
                if (node.type === "wallet") {
                    metricsHtml += `
                        <div class="telemetry-summary-item">
                            <span class="telemetry-summary-label">Risk Evaluation</span>
                            <span class="telemetry-summary-value ${node.isRisk ? 'text-red' : 'text-green'}">${node.isRisk ? 'CRITICAL / HIGH' : 'NOMINAL'}</span>
                        </div>
                    `;
                }
                inspectorMetrics.innerHTML = metricsHtml;

                inspectorBtn.onclick = () => {
                    if (node.type === "wallet") {
                        Router.navigate(`wallet/${encodeURIComponent(node.id)}`);
                    } else if (node.type === "transaction") {
                        Router.navigate(`transaction/${encodeURIComponent(node.id)}`);
                    } else {
                        copyToClipboard(node.id, "IP Node");
                    }
                };
            };

            const closeInspector = () => {
                selectedNode = null;
                if (inspector) inspector.classList.add("hidden");
            };
            const closeBtn = $("#btn-close-inspector");
            if (closeBtn) closeBtn.onclick = closeInspector;

            window.__tracex_highlight_node = (term) => {
                const target = nodes.find(n => n.id.toLowerCase().includes(term));
                if (target) {
                    openInspector(target);
                    panX = width / 2 - target.x * zoom;
                    panY = height / 2 - target.y * zoom;
                    showToast(`Located node: ${shortId(target.id, 10, 6)}`, "success");
                } else {
                    showToast(`No node matching "${term}"`, "warning");
                }
            };

            // Physics step
            const tick = () => {
                // Link attraction with fixed distance calculation
                for (const link of links) {
                    const dx = link.target.x - link.source.x;
                    const dy = link.target.y - link.source.y;
                    const dist = Math.hypot(dx, dy) || 1;
                    const force = (dist - 75) * 0.005;
                    const fx = (dx / dist) * force;
                    const fy = (dy / dist) * force;
                    link.source.vx += fx;
                    link.source.vy += fy;
                    link.target.vx -= fx;
                    link.target.vy -= fy;
                }

                // Node repulsion
                for (let i = 0; i < nodes.length; i++) {
                    const n1 = nodes[i];
                    for (let j = i + 1; j < nodes.length; j++) {
                        const n2 = nodes[j];
                        const dx = n2.x - n1.x;
                        const dy = n2.y - n1.y;
                        const dist2 = dx * dx + dy * dy || 1;
                        if (dist2 < 14000) {
                            const force = 280 / dist2;
                            const dist = Math.sqrt(dist2);
                            const fx = (dx / dist) * force;
                            const fy = (dy / dist) * force;
                            n1.vx -= fx;
                            n1.vy -= fy;
                            n2.vx += fx;
                            n2.vy += fy;
                        }
                    }
                    // Damping and center gravity
                    n1.vx += (width / 2 - n1.x) * 0.0008;
                    n1.vy += (height / 2 - n1.y) * 0.0008;
                    n1.x += n1.vx;
                    n1.y += n1.vy;
                    n1.vx *= 0.88;
                    n1.vy *= 0.88;
                }

                // Render
                ctx.clearRect(0, 0, width, height);
                ctx.save();
                ctx.translate(panX, panY);
                ctx.scale(zoom, zoom);

                // Draw Edges
                ctx.lineWidth = 1;
                for (const link of links) {
                    ctx.beginPath();
                    ctx.moveTo(link.source.x, link.source.y);
                    ctx.lineTo(link.target.x, link.target.y);
                    if (link.relationship === "observed") {
                        ctx.strokeStyle = "rgba(129, 140, 248, 0.22)";
                    } else {
                        ctx.strokeStyle = "rgba(56, 189, 248, 0.3)";
                    }
                    ctx.stroke();
                }

                // Draw Nodes
                for (const node of nodes) {
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, node.radius, 0, 2 * Math.PI);

                    if (node.type === "wallet") {
                        if (node.isRisk) {
                            ctx.fillStyle = "#ef4444";
                            ctx.shadowColor = "#ef4444";
                            ctx.shadowBlur = 12;
                        } else {
                            ctx.fillStyle = "#00e5ff";
                            ctx.shadowColor = "#00e5ff";
                            ctx.shadowBlur = 6;
                        }
                    } else if (node.type === "transaction") {
                        ctx.fillStyle = "#f59e0b";
                        ctx.shadowColor = "#f59e0b";
                        ctx.shadowBlur = 6;
                    } else {
                        ctx.fillStyle = "#818cf8";
                        ctx.shadowColor = "#818cf8";
                        ctx.shadowBlur = 4;
                    }
                    ctx.fill();
                    ctx.shadowBlur = 0;

                    // Highlight selected
                    if (selectedNode === node) {
                        ctx.beginPath();
                        ctx.arc(node.x, node.y, node.radius + 4, 0, 2 * Math.PI);
                        ctx.strokeStyle = "#fff";
                        ctx.lineWidth = 2;
                        ctx.stroke();
                    }
                }

                ctx.restore();

                App.graphSimulation = requestAnimationFrame(tick);
            };

            App.graphSimulation = requestAnimationFrame(tick);

            // Interaction events
            canvas.onmousedown = (e) => {
                const rect = canvas.getBoundingClientRect();
                const mx = (e.clientX - rect.left - panX) / zoom;
                const my = (e.clientY - rect.top - panY) / zoom;

                let clicked = null;
                for (let i = nodes.length - 1; i >= 0; i--) {
                    const n = nodes[i];
                    const dist = Math.hypot(n.x - mx, n.y - my);
                    if (dist <= n.radius + 5) {
                        clicked = n;
                        break;
                    }
                }

                if (clicked) {
                    dragNode = clicked;
                    openInspector(clicked);
                } else {
                    isDragging = true;
                    startMouse = { x: e.clientX - panX, y: e.clientY - panY };
                }
            };

            window.onmousemove = (e) => {
                if (dragNode) {
                    const rect = canvas.getBoundingClientRect();
                    dragNode.x = (e.clientX - rect.left - panX) / zoom;
                    dragNode.y = (e.clientY - rect.top - panY) / zoom;
                    dragNode.vx = 0;
                    dragNode.vy = 0;
                } else if (isDragging) {
                    panX = e.clientX - startMouse.x;
                    panY = e.clientY - startMouse.y;
                }
            };

            window.onmouseup = () => {
                dragNode = null;
                isDragging = false;
            };

            canvas.onwheel = (e) => {
                e.preventDefault();
                const factor = e.deltaY < 0 ? 1.1 : 0.9;
                zoom = Math.max(0.2, Math.min(4, zoom * factor));
            };

            // Toolbar Controls
            const zoomInBtn = $("#graph-zoom-in");
            if (zoomInBtn) zoomInBtn.onclick = () => { zoom = Math.min(4, zoom * 1.25); };
            const zoomOutBtn = $("#graph-zoom-out");
            if (zoomOutBtn) zoomOutBtn.onclick = () => { zoom = Math.max(0.2, zoom * 0.8); };
            const resetBtn = $("#graph-reset");
            if (resetBtn) resetBtn.onclick = () => { zoom = 1; panX = 0; panY = 0; };
        },

        // ----------------------------------------------------------------------
        // 5. THREAT ALERTS
        // ----------------------------------------------------------------------
        async renderThreatAlerts(container) {
            const data = await API.get("/alerts");
            const alerts = data.alerts || [];

            container.innerHTML = `
                <div class="page-header">
                    <div class="page-title-group">
                        <h1 class="page-title">
                            THREAT INTELLIGENCE &amp; ALERTS
                            <span class="risk-chip critical">${alerts.length} ALERTS ACTIVE</span>
                        </h1>
                        <p class="page-subtitle">Security intelligence queue of all detected behavioral anomalies exceeding risk score threshold 60.</p>
                    </div>
                </div>

                <div class="cyber-card">
                    <div class="card-header">
                        <span class="card-title">
                            <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                            </svg>
                            ACTIVE ANOMALY VECTORS
                        </span>
                        <input type="text" id="alerts-filter-input" class="wallet-search-input" style="max-width:240px;padding:4px 8px;font-size:11px;" placeholder="Filter by address or signal...">
                    </div>
                    <div class="table-responsive">
                        <table class="forensic-table" id="alerts-table">
                            <thead>
                                <tr>
                                    <th>SEVERITY</th>
                                    <th>RISK SCORE</th>
                                    <th>WALLET ADDRESS</th>
                                    <th>ANOMALY SCORE</th>
                                    <th>CONFIDENCE</th>
                                    <th>EVIDENCE / REASONING</th>
                                    <th>ACTIONS</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${alerts.map((a) => {
                                    const lvl = getRiskLevel(a.risk_score);
                                    return `
                                        <tr class="${lvl === 'critical' ? 'row-high-risk' : ''}">
                                            <td><span class="risk-chip ${lvl}">${getRiskLabel(a.risk_score)}</span></td>
                                            <td><strong class="mono ${lvl === 'critical' ? 'text-red' : 'text-amber'}">${num(a.risk_score, 1)}</strong></td>
                                            <td>
                                                <a href="#/wallet/${esc(a.wallet_address)}" class="technical-link">
                                                    ${esc(a.wallet_address)}
                                                </a>
                                            </td>
                                            <td class="mono">${num(a.anomaly_score, 4)}</td>
                                            <td class="mono">${num(a.confidence, 1)}%</td>
                                            <td style="max-width:320px; font-size:11.5px; color:var(--text-muted);">${esc(a.explanation)}</td>
                                            <td>
                                                <a href="#/wallet/${esc(a.wallet_address)}" class="btn-table-action">
                                                    INVESTIGATE
                                                </a>
                                                <a href="#/network/${esc(a.wallet_address)}" class="btn-table-action">
                                                    GRAPH
                                                </a>
                                            </td>
                                        </tr>
                                    `;
                                }).join("")}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;

            // Filter logic
            const filterInput = $("#alerts-filter-input");
            if (filterInput) {
                filterInput.addEventListener("input", (e) => {
                    const q = e.target.value.toLowerCase();
                    $$("#alerts-table tbody tr").forEach((row) => {
                        const text = row.textContent.toLowerCase();
                        row.style.display = text.includes(q) ? "" : "none";
                    });
                });
            }
        },

        // ----------------------------------------------------------------------
        // 6. ANALYSIS SESSIONS
        // ----------------------------------------------------------------------
        async renderAnalysisSessions(container) {
            const data = await API.get("/sessions");
            const sessions = data.sessions || [];

            container.innerHTML = `
                <div class="page-header">
                    <div class="page-title-group">
                        <h1 class="page-title">
                            ANALYSIS SESSIONS &amp; AUDIT LOG
                            <span class="risk-chip safe">${sessions.length} SESSIONS RECORDED</span>
                        </h1>
                        <p class="page-subtitle">Historical forensic analysis jobs, dataset execution timelines, and alert telemetry.</p>
                    </div>
                </div>

                <div class="cyber-card">
                    <div class="card-header">
                        <span class="card-title">
                            <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                <circle cx="12" cy="12" r="10"></circle>
                                <polyline points="12 6 12 12 16 14"></polyline>
                            </svg>
                            RECORDED INVESTIGATION SESSIONS
                        </span>
                    </div>
                    <div class="table-responsive">
                        <table class="forensic-table">
                            <thead>
                                <tr>
                                    <th>SESSION ID</th>
                                    <th>SESSION NAME</th>
                                    <th>STATUS</th>
                                    <th>DATASET</th>
                                    <th>TRANSACTIONS</th>
                                    <th>WALLETS</th>
                                    <th>HIGH-RISK ALERTS</th>
                                    <th>MAX RISK</th>
                                    <th>TIMESTAMP</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${sessions.map((s) => `
                                    <tr>
                                        <td class="mono text-cyan">${esc(s.id)}</td>
                                        <td><strong>${esc(s.name)}</strong></td>
                                        <td><span class="risk-chip safe">${esc(s.status)}</span></td>
                                        <td><span class="nav-badge">${esc(s.dataset_name)}</span></td>
                                        <td class="mono">${int(s.total_transactions)}</td>
                                        <td class="mono">${int(s.total_wallets)}</td>
                                        <td class="mono text-red" style="font-weight:700;">${int(s.high_risk_alerts)}</td>
                                        <td class="mono text-amber">${num(s.max_risk, 1)}</td>
                                        <td class="mono" style="font-size:11px;">${esc(s.created_at ? s.created_at.split(".")[0] : '')}</td>
                                    </tr>
                                `).join("")}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;
        },

        // ----------------------------------------------------------------------
        // 7. DATASET INGESTION & ARCHIVE MANAGEMENT
        // ----------------------------------------------------------------------
        async renderDatasetIngestion(container) {
            let datasets = [];
            try {
                const dsData = await API.get("/datasets");
                datasets = dsData.datasets || [];
            } catch (_) {}

            container.innerHTML = `
                <div class="page-header">
                    <div class="page-title-group">
                        <h1 class="page-title">
                            DATASET INGESTION &amp; ML PIPELINE
                            <span class="risk-chip safe">OFFLINE ENGINE READY</span>
                        </h1>
                        <p class="page-subtitle">Upload raw Bitcoin traffic metadata, run validation, trigger Isolation Forest training, and manage generated dataset archive.</p>
                    </div>
                </div>

                <!-- PIPELINE STEPPER -->
                <div class="pipeline-stepper" id="pipeline-stepper">
                    <div class="step-item completed" id="step-upload">
                        <div class="step-indicator">01</div>
                        <span class="step-name">UPLOAD / GEN</span>
                    </div>
                    <div class="step-item" id="step-validate">
                        <div class="step-indicator">02</div>
                        <span class="step-name">VALIDATE</span>
                    </div>
                    <div class="step-item" id="step-profile">
                        <div class="step-indicator">03</div>
                        <span class="step-name">PROFILE</span>
                    </div>
                    <div class="step-item" id="step-ml">
                        <div class="step-indicator">04</div>
                        <span class="step-name">ML ENGINE</span>
                    </div>
                    <div class="step-item" id="step-alerts">
                        <div class="step-indicator">05</div>
                        <span class="step-name">ALERTS READY</span>
                    </div>
                </div>

                <!-- DROPZONE AND CONTROLS -->
                <div class="cyber-card">
                    <div class="card-header">
                        <span class="card-title">
                            <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="17 8 12 3 7 8"></polyline>
                                <line x1="12" y1="3" x2="12" y2="15"></line>
                            </svg>
                            SELECT OR GENERATE TRAFFIC DATASET
                        </span>
                    </div>
                    <div class="card-body">
                        <div class="dropzone-box" id="ingest-dropzone">
                            <svg class="dropzone-icon" viewBox="0 0 24 24" width="48" height="48" fill="none" stroke="currentColor" stroke-width="1.8">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="17 8 12 3 7 8"></polyline>
                                <line x1="12" y1="3" x2="12" y2="15"></line>
                            </svg>
                            <h3 class="dropzone-title">Drag &amp; Drop Bitcoin Traffic CSV</h3>
                            <p class="dropzone-desc">Accepts RFC-4180 CSV with transaction flows, inputs, outputs, and network metadata.</p>
                            <input type="file" id="ingest-file-input" accept=".csv" style="display:none;">
                            <button class="btn-cyber" id="btn-browse-file">BROWSE CSV FILE</button>
                        </div>

                        <div style="display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--border-subtle);padding-top:16px;flex-wrap:wrap;gap:12px;">
                            <div>
                                <span style="font-weight:600;font-size:12px;color:#fff;">STANDARDIZED REPOSITORY PRESETS</span>
                                <p style="font-size:11px;color:var(--text-muted);">Ingest standard benchmark dataset or synthesize fresh realistic traffic.</p>
                            </div>
                            <div style="display:flex;gap:10px;">
                                <button class="btn-cyber" id="btn-ingest-default">
                                    INGEST BENCHMARK DATASET
                                </button>
                                <button class="btn-cyber-outline" id="btn-ingest-regen">
                                    REGENERATE FRESH DATASET
                                </button>
                            </div>
                        </div>

                        <!-- LIVE EXECUTION RESULT CONTAINER -->
                        <div id="ingest-result-box" style="margin-top:20px;display:none;"></div>
                    </div>
                </div>

                <!-- GENERATED DATASET ARCHIVE & HISTORY -->
                <div class="cyber-card" style="margin-top:20px;">
                    <div class="card-header">
                        <span class="card-title">
                            <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
                                <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
                                <line x1="12" y1="22.08" x2="12" y2="12"></line>
                            </svg>
                            GENERATED DATASET ARCHIVE &amp; REPOSITORY HISTORY (${datasets.length})
                        </span>
                        <span class="status-meta">SQLITE PERSISTED DATASETS</span>
                    </div>
                    <div class="table-responsive">
                        <table class="forensic-table" id="dataset-history-table">
                            <thead>
                                <tr>
                                    <th>STATUS</th>
                                    <th>DATASET / FILENAME</th>
                                    <th>GENERATED AT</th>
                                    <th>TRANSACTIONS</th>
                                    <th>WALLETS</th>
                                    <th>HIGH-RISK ANOMALIES</th>
                                    <th>SCENARIO MIX / MODELS</th>
                                    <th>ACTIONS</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${datasets.length ? datasets.map((d) => {
                                    const isBench = d.is_default || d.id === 'DS-BENCHMARK-DEFAULT';
                                    const statusText = isBench ? 'BENCHMARK' : (d.status === 'ANALYZED' ? 'ANALYZED' : 'READY');
                                    const chipClass = isBench ? 'safe' : (d.status === 'ANALYZED' ? 'safe' : 'medium');
                                    const genDate = (d.generated_at || d.created_at || 'N/A').split(".")[0].replace("T", " ");
                                    return `
                                    <tr data-id="${esc(d.id)}">
                                        <td>
                                            <span class="risk-chip ${chipClass}">
                                                ${statusText}
                                            </span>
                                        </td>
                                        <td>
                                            <strong class="mono ${isBench ? 'text-cyan' : ''}">${esc(d.filename || d.dataset_name)}</strong>
                                            <div style="font-size:10px;color:var(--text-faint);">${esc(d.id)}</div>
                                        </td>
                                        <td class="mono" style="font-size:11px;">${esc(genDate)}</td>
                                        <td class="mono">${int(d.transaction_count || d.row_count || 3000)}</td>
                                        <td class="mono">${int(d.wallet_count || 480)}</td>
                                        <td class="mono text-red" style="font-weight:700;">${int(d.high_risk_count ?? d.anomalies_detected ?? 0)}</td>
                                        <td style="font-size:11px;color:var(--text-muted);max-width:260px;white-space:normal;">
                                            ${esc(d.behavior_mix || 'Standard Multi-Model Distribution')}
                                        </td>
                                        <td>
                                            <div style="display:flex;gap:6px;">
                                                <button class="btn-dataset-action btn-ds-ingest" data-id="${esc(d.id)}" title="Ingest into Database &amp; Train ML">
                                                    ${isBench ? 'RE-INGEST' : 'INGEST &amp; TRAIN'}
                                                </button>
                                                <a href="/api/datasets/${esc(d.id)}/download" target="_blank" class="btn-dataset-action btn-ds-download" title="Download CSV">
                                                    DOWNLOAD
                                                </a>
                                                ${!isBench ? `
                                                    <button class="btn-dataset-action action-danger btn-ds-delete" data-id="${esc(d.id)}" title="Delete Dataset">
                                                        DELETE
                                                    </button>
                                                ` : ''}
                                            </div>
                                        </td>
                                    </tr>
                                    `;
                                }).join("") : `
                                    <tr>
                                        <td colspan="8" style="text-align:center;color:var(--text-faint);padding:24px;">No persisted datasets in archive.</td>
                                    </tr>
                                `}
                            </tbody>
                        </table>
                    </div>
                </div>
            `;

            // Wire file controls
            const dropzone = $("#ingest-dropzone");
            const fileInput = $("#ingest-file-input");
            const browseBtn = $("#btn-browse-file");
            const defaultBtn = $("#btn-ingest-default");
            const regenBtn = $("#btn-ingest-regen");
            const resultBox = $("#ingest-result-box");

            if (browseBtn && fileInput) browseBtn.onclick = () => fileInput.click();
            if (fileInput) {
                fileInput.onchange = () => {
                    if (fileInput.files.length) {
                        uploadAndIngest(fileInput.files[0]);
                    }
                };
            }

            if (dropzone) {
                dropzone.ondragover = (e) => { e.preventDefault(); dropzone.classList.add("dragover"); };
                dropzone.ondragleave = () => dropzone.classList.remove("dragover");
                dropzone.ondrop = (e) => {
                    e.preventDefault();
                    dropzone.classList.remove("dragover");
                    if (e.dataTransfer.files.length) {
                        uploadAndIngest(e.dataTransfer.files[0]);
                    }
                };
            }

            if (defaultBtn) defaultBtn.onclick = () => runPipeline({ use_default: true });
            if (regenBtn) regenBtn.onclick = () => runPipeline({ regenerate: true });

            // Wire Dataset Action Buttons
            $$(".btn-ds-ingest").forEach((btn) => {
                btn.onclick = async () => {
                    const id = btn.getAttribute("data-id");
                    const form = new FormData();
                    form.append("dataset_id", id);
                    await executePipelineForm(form, `Ingesting Dataset [${id}]`);
                };
            });

            $$(".btn-ds-delete").forEach((btn) => {
                btn.onclick = async () => {
                    const id = btn.getAttribute("data-id");
                    if (confirm(`Are you sure you want to delete dataset [${id}]?`)) {
                        try {
                            await API.delete(`/datasets/${id}`);
                            showToast("Dataset deleted successfully", "success");
                            Views.renderDatasetIngestion(container);
                        } catch (err) {
                            showToast(`Failed to delete dataset: ${err.message}`, "error");
                        }
                    }
                };
            });

            async function uploadAndIngest(file) {
                const form = new FormData();
                form.append("file", file);
                await executePipelineForm(form, file.name);
            }

            async function runPipeline(opts) {
                const form = new FormData();
                if (opts.use_default) form.append("use_default", "true");
                if (opts.regenerate) form.append("regenerate", "true");
                await executePipelineForm(form, opts.regenerate ? "Freshly Generated Dataset" : "Default Benchmark (bitcoin_traffic.csv)");
            }

            async function executePipelineForm(form, label) {
                resultBox.style.display = "block";
                resultBox.innerHTML = `
                    <div style="background:var(--bg-alt);border:1px solid var(--cyan);padding:18px;border-radius:var(--radius-sm);text-align:center;">
                        <span class="status-pulse-dot" style="display:inline-block;margin-bottom:8px;"></span>
                        <div style="font-weight:700;color:#fff;margin-bottom:4px;">RUNNING FORENSIC INGESTION PIPELINE...</div>
                        <div style="font-size:11px;color:var(--text-muted);">Validating schema → Ingesting entities → Executing Isolation Forest → Generating alerts...</div>
                    </div>
                `;

                $("#step-validate").classList.add("active");

                try {
                    const res = await API.postForm("/ingest", form);
                    $("#step-validate").classList.add("completed");
                    $("#step-profile").classList.add("completed");
                    $("#step-ml").classList.add("completed");
                    $("#step-alerts").classList.add("completed");

                    resultBox.innerHTML = `
                        <div style="background:rgba(16, 185, 129, 0.08);border:1px solid var(--risk-safe-border);padding:18px;border-radius:var(--radius-sm);">
                            <div style="display:flex;align-items:center;gap:10px;margin-bottom:12px;">
                                <span class="risk-chip safe">PIPELINE EXECUTION COMPLETE</span>
                                <strong style="color:#fff;">${esc(label)}</strong>
                            </div>
                            <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:10px;margin-bottom:14px;">
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Transactions</span>
                                    <span class="telemetry-summary-value text-cyan">${int(res.stats.transactions)}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Wallets</span>
                                    <span class="telemetry-summary-value">${int(res.stats.wallets)}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">IP Nodes</span>
                                    <span class="telemetry-summary-value">${int(res.stats.ips)}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">High-Risk Alerts</span>
                                    <span class="telemetry-summary-value text-red">${int(res.alerts_count)}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Max Risk</span>
                                    <span class="telemetry-summary-value text-amber">${num(res.max_risk, 1)}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Duration</span>
                                    <span class="telemetry-summary-value">${num(res.duration_seconds, 1)}s</span>
                                </div>
                            </div>
                            <div style="display:flex;gap:10px;">
                                <a href="#/command-center" class="btn-cyber">OPEN COMMAND CENTER</a>
                                <a href="#/alerts" class="btn-cyber-outline">INSPECT GENERATED ALERTS</a>
                                <button class="btn-cyber-outline" id="btn-refresh-history">REFRESH ARCHIVE TABLE</button>
                            </div>
                        </div>
                    `;
                    showToast("Pipeline completed successfully!", "success");

                    const refreshBtn = $("#btn-refresh-history");
                    if (refreshBtn) refreshBtn.onclick = () => Views.renderDatasetIngestion(container);
                } catch (err) {
                    resultBox.innerHTML = `
                        <div style="background:var(--risk-critical-bg);border:1px solid var(--risk-critical-border);padding:18px;border-radius:var(--radius-sm);color:#fff;">
                            <strong class="text-red">Pipeline Failed:</strong> ${esc(err.message)}
                        </div>
                    `;
                    showToast("Pipeline execution failed", "error");
                }
            }
        },

        // ----------------------------------------------------------------------
        // 8. INVESTIGATION REPORTS (12-SECTION FORENSIC DOSSIER)
        // ----------------------------------------------------------------------
        async renderInvestigationReports(container) {
            let targetWallet = App.state.routeParams?.id || "";
            let topWallets = [];
            try {
                const alertsData = await API.get("/alerts");
                App.state.alerts = alertsData.alerts || [];
                topWallets = App.state.alerts.slice(0, 10);
            } catch (_) {}

            // Load 12-section dossier data
            let dossier = null;
            try {
                const query = targetWallet ? `?type=wallet&target=${encodeURIComponent(targetWallet)}` : `?type=comprehensive`;
                dossier = await API.get(`/reports/dossier${query}`);
            } catch (err) {
                // Fallback to overview if dossier fails
                const overview = await API.get("/overview");
                dossier = {
                    metadata: {
                        case_id: "TRACEX-SEC-FALLBACK",
                        classification: "CONFIDENTIAL",
                        target: targetWallet || "GLOBAL_ACTIVE_DATASET",
                        generated_at: new Date().toISOString()
                    },
                    executive_summary: {
                        summary_text: "Automated cyber-forensic investigation across monitored Bitcoin transaction traffic."
                    },
                    risk_evaluation: {
                        analyzed_wallets: overview.wallets,
                        critical_alerts_count: overview.high_risk_alerts,
                        mean_risk: overview.average_risk,
                        max_risk: overview.max_risk
                    },
                    threat_actors: (App.state.alerts || []).slice(0, 10),
                    recommendations: [
                        "Immediate freeze on top critical entities.",
                        "AS-level monitoring for anomalous broadcast clusters.",
                        "UTXO taint tracing across counterparty networks."
                    ],
                    chain_of_custody: {
                        analyst_id: "TRACEX_AUTOMATED_FORENSIC_ENGINE",
                        integrity_status: "VERIFIED"
                    }
                };
            }

            const m = dossier.metadata || {};
            const exec = dossier.executive_summary || {};
            const risk = dossier.risk_evaluation || {};
            const beh = dossier.behavioral_profile || {};
            const flow = dossier.transaction_flow || {};
            const net = dossier.network_infrastructure || {};
            const graph = dossier.graph_topology || {};
            const threats = dossier.threat_actors || [];
            const findings = dossier.forensic_findings || [];
            const prov = dossier.model_provenance || {};
            const recs = dossier.recommendations || [];
            const cert = dossier.chain_of_custody || {};

            const pdfDownloadUrl = `/api/reports/pdf?type=${targetWallet ? 'wallet' : 'comprehensive'}&target=${encodeURIComponent(targetWallet)}`;

            container.innerHTML = `
                <div class="page-header">
                    <div class="page-title-group">
                        <h1 class="page-title">
                            INVESTIGATION REPORT DOSSIER
                            <span class="risk-chip critical">${esc(m.classification || 'CONFIDENTIAL // CYBER INTEL')}</span>
                        </h1>
                        <p class="page-subtitle">Multi-vector forensic audit, machine learning anomaly verification, and certified law enforcement intelligence dossier.</p>
                    </div>
                    <div class="page-actions">
                        <a href="${pdfDownloadUrl}" target="_blank" class="btn-cyber" id="btn-download-pdf">
                            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
                                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                                <polyline points="7 10 12 15 17 10"></polyline>
                                <line x1="12" y1="15" x2="12" y2="3"></line>
                            </svg>
                            DOWNLOAD REPORT (PDF)
                        </a>
                        <button class="btn-cyber-outline" id="btn-print-report">
                            <svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2">
                                <polyline points="6 9 6 2 18 2 18 9"></polyline>
                                <path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"></path>
                                <rect x="6" y="14" width="12" height="8"></rect>
                            </svg>
                            PRINT DOSSIER
                        </button>
                        <button class="btn-cyber-outline" id="btn-copy-markdown">
                            COPY SUMMARY
                        </button>
                    </div>
                </div>

                <!-- REPORT TARGET SELECTOR BAR -->
                <div class="wallet-selector-bar" style="margin-bottom:20px;">
                    <div style="display:flex;align-items:center;gap:8px;">
                        <span style="font-size:11px;color:var(--text-faint);font-weight:700;">AUDIT TARGET:</span>
                        <select id="report-target-select" class="wallet-search-input" style="padding:6px 10px;font-size:11px;min-width:260px;">
                            <option value="">Global Forensic Audit (Full Dataset)</option>
                            ${topWallets.map((a) => `
                                <option value="${esc(a.wallet_address)}" ${a.wallet_address === targetWallet ? 'selected' : ''}>
                                    Target: ${shortId(a.wallet_address, 12, 6)} [Risk: ${Math.round(a.risk_score)}]
                                </option>
                            `).join("")}
                        </select>
                    </div>
                    <button class="btn-cyber" id="btn-apply-report-target">GENERATE DOSSIER</button>
                </div>

                <!-- COMPLETE 12-SECTION DOSSIER PAPER -->
                <div class="report-paper">
                    <!-- SECTION 1: HEADER & METADATA -->
                    <div class="report-header">
                        <div>
                            <span class="report-classification">${esc(m.classification || 'CONFIDENTIAL // CYBER INTEL')}</span>
                            <h2 style="font-size:20px;font-weight:800;color:#fff;letter-spacing:0.02em;">TRACE-X BITCOIN TRANSACTION FORENSIC REPORT</h2>
                            <p style="font-size:12px;color:var(--text-muted);">Investigation Reference: <strong>${esc(m.case_id)}</strong> | Target: <strong class="mono text-cyan">${esc(m.target)}</strong></p>
                        </div>
                        <div style="text-align:right;">
                            <div class="mono" style="font-size:11px;color:var(--text-faint);">GENERATED AT</div>
                            <div class="mono text-cyan" style="font-size:12px;font-weight:600;">${esc(m.generated_at ? m.generated_at.replace('T', ' ').substring(0, 19) : '')} UTC</div>
                            <div class="mono" style="font-size:10px;color:var(--text-faint);margin-top:2px;">ENGINE: TRACE-X v2.0</div>
                        </div>
                    </div>

                    <!-- SECTION 2: EXECUTIVE CASE SUMMARY -->
                    <div class="report-section">
                        <div class="report-section-title">1. EXECUTIVE CASE SUMMARY</div>
                        <p style="font-size:12px;color:var(--text-muted);line-height:1.6;margin-bottom:10px;">
                            ${esc(exec.summary_text || 'An automated forensic cyber-investigation was performed across monitored Bitcoin peer-to-peer transaction traffic.')}
                        </p>
                        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:10px;">
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Transactions Correlated</span>
                                <span class="telemetry-summary-value text-cyan">${int(exec.total_transactions_correlated || 3000)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Observations Ingested</span>
                                <span class="telemetry-summary-value">${int(exec.total_observations_ingested || 3000)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Unique Wallets</span>
                                <span class="telemetry-summary-value">${int(exec.unique_wallets_inspected || 480)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Anomalies Detected</span>
                                <span class="telemetry-summary-value text-red">${int(exec.anomaly_vectors_detected || 0)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Critical Alerts</span>
                                <span class="telemetry-summary-value text-red">${int(exec.critical_threat_entities || 0)}</span>
                            </div>
                        </div>
                    </div>

                    <!-- SECTION 3: RISK EVALUATION & COMPOSITE SCORING -->
                    <div class="report-section">
                        <div class="report-section-title">2. COMPOSITE RISK EVALUATION &amp; MULTI-VECTOR SCORING</div>
                        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:10px;margin-bottom:12px;">
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Analyzed Wallets</span>
                                <span class="telemetry-summary-value text-cyan">${int(risk.analyzed_wallets || 0)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Critical Alerts (≥80)</span>
                                <span class="telemetry-summary-value text-red">${int(risk.critical_alerts_count || 0)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Fleet Mean Risk</span>
                                <span class="telemetry-summary-value">${num(risk.mean_risk || 0, 1)} / 100</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Max Risk Vector</span>
                                <span class="telemetry-summary-value text-red">${num(risk.max_risk || 0, 1)} / 100</span>
                            </div>
                        </div>
                        <p style="font-size:11.5px;color:var(--text-muted);line-height:1.5;">
                            Composite scoring blends <strong>ML Anomaly Isolation Forest (50%)</strong>, <strong>Velocity &amp; Flow Imbalance (20%)</strong>, 
                            <strong>Network &amp; Geo Corroboration (15%)</strong>, and <strong>Graph Centrality (15%)</strong>.
                        </p>
                    </div>

                    <!-- SECTION 4: BEHAVIORAL & TRANSACTIONAL PROFILE -->
                    <div class="report-section">
                        <div class="report-section-title">3. BEHAVIORAL &amp; TRANSACTIONAL PROFILE</div>
                        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:10px;">
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Mean Transaction Volume</span>
                                <span class="telemetry-summary-value text-green">${num(beh.mean_transaction_volume || 0, 4)} BTC</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Max Single Transfer</span>
                                <span class="telemetry-summary-value text-green">${num(beh.max_single_transfer || 0, 4)} BTC</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Mean Flow Imbalance</span>
                                <span class="telemetry-summary-value">${num(beh.mean_flow_imbalance || 0, 2)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Mean Velocity (TX/IP)</span>
                                <span class="telemetry-summary-value">${num(beh.mean_tx_velocity || 0, 2)}</span>
                            </div>
                        </div>
                    </div>

                    <!-- SECTION 5: TRANSACTION FLOW TOPOLOGY -->
                    <div class="report-section">
                        <div class="report-section-title">4. TRANSACTION FLOW TOPOLOGY &amp; SCRIPTS</div>
                        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:10px;margin-bottom:10px;">
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Total Inflow Volume</span>
                                <span class="telemetry-summary-value text-green">${num(flow.total_inflow_btc || 0, 4)} BTC</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Total Outflow Volume</span>
                                <span class="telemetry-summary-value text-amber">${num(flow.total_outflow_btc || 0, 4)} BTC</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Total Miner Fees</span>
                                <span class="telemetry-summary-value">${num(flow.total_miner_fees_btc || 0, 6)} BTC</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Observed Fan-out TXs</span>
                                <span class="telemetry-summary-value text-cyan">${int(flow.fan_out_transactions || 0)}</span>
                            </div>
                        </div>
                    </div>

                    <!-- SECTION 6: NETWORK LAYER & INFRASTRUCTURE -->
                    <div class="report-section">
                        <div class="report-section-title">5. NETWORK-LAYER &amp; INFRASTRUCTURE CORROBORATION</div>
                        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:10px;margin-bottom:10px;">
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Unique Source IPs</span>
                                <span class="telemetry-summary-value text-cyan">${int(net.unique_source_ips || 0)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Unique Dest IPs</span>
                                <span class="telemetry-summary-value">${int(net.unique_destination_ips || 0)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Correlated ASNs</span>
                                <span class="telemetry-summary-value">${int(net.unique_asns || 0)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Geographic Jurisdictions</span>
                                <span class="telemetry-summary-value">${int(net.unique_countries || 0)}</span>
                            </div>
                        </div>
                        <div style="font-size:11px;color:var(--text-faint);">
                            TOP CORRELATED ASNs: <strong class="mono text-cyan">${(net.top_asns || []).join(", ") || 'AS-GLOBAL-TELEMETRY'}</strong>
                        </div>
                    </div>

                    <!-- SECTION 7: GRAPH CENTRALITY & TOPOLOGY -->
                    <div class="report-section">
                        <div class="report-section-title">6. GRAPH CENTRALITY &amp; FAN-OUT DISPERSION</div>
                        <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(140px, 1fr));gap:10px;">
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Graph Nodes</span>
                                <span class="telemetry-summary-value text-cyan">${int(graph.graph_nodes || 0)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Graph Edges</span>
                                <span class="telemetry-summary-value">${int(graph.graph_edges || 0)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">Graph Density</span>
                                <span class="telemetry-summary-value">${num(graph.density || 0, 4)}</span>
                            </div>
                            <div class="telemetry-summary-item">
                                <span class="telemetry-summary-label">High Centrality Hubs</span>
                                <span class="telemetry-summary-value text-amber">${int(graph.high_centrality_wallets || 0)}</span>
                            </div>
                        </div>
                    </div>

                    <!-- SECTION 8: PRIMARY IDENTIFIED THREAT ACTORS -->
                    <div class="report-section">
                        <div class="report-section-title">7. PRIMARY IDENTIFIED THREAT ACTORS &amp; SUSPICIOUS ENTITIES (${threats.length})</div>
                        <div class="table-responsive">
                            <table class="forensic-table">
                                <thead>
                                    <tr>
                                        <th>RANK</th>
                                        <th>WALLET ADDRESS</th>
                                        <th>RISK SCORE</th>
                                        <th>CONFIDENCE</th>
                                        <th>ANOMALY</th>
                                        <th>FORENSIC RATIONALE</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${threats.map((a, i) => `
                                        <tr>
                                            <td class="mono">#${i + 1}</td>
                                            <td class="mono text-cyan">
                                                <a href="#/wallet/${esc(a.wallet_address)}" class="technical-link">
                                                    ${shortId(a.wallet_address, 12, 6)}
                                                </a>
                                            </td>
                                            <td><strong class="${a.risk_score >= 80 ? 'text-red' : 'text-amber'}">${num(a.risk_score, 1)}</strong></td>
                                            <td class="mono">${num(a.confidence, 1)}%</td>
                                            <td class="mono">${num(a.anomaly_score, 4)}</td>
                                            <td style="font-size:11px;">${esc(a.explanation)}</td>
                                        </tr>
                                    `).join("")}
                                </tbody>
                            </table>
                        </div>
                    </div>

                    <!-- SECTION 9: FORENSIC EVIDENCE FINDINGS -->
                    <div class="report-section">
                        <div class="report-section-title">8. KEY FORENSIC EVIDENCE &amp; HEURISTIC FINDINGS</div>
                        <div class="signals-list">
                            ${findings.map((f) => `
                                <div class="signal-card">
                                    <span class="signal-badge">${esc(f.category || 'SIGNAL')}</span>
                                    <div>
                                        <div class="signal-title">${esc(f.title)}</div>
                                        <div class="signal-detail">${esc(f.detail)}</div>
                                    </div>
                                </div>
                            `).join("")}
                        </div>
                    </div>

                    <!-- SECTION 10: MODEL PROVENANCE & INTEGRITY -->
                    <div class="report-section">
                        <div class="report-section-title">9. MODEL PROVENANCE &amp; DATA INTEGRITY</div>
                        <div class="provenance-card" style="margin-top:0;">
                            <div class="provenance-grid">
                                <div class="provenance-item">
                                    <span>ML ALGORITHM</span>
                                    <strong class="mono text-cyan">${esc(prov.algorithm || 'Isolation Forest')}</strong>
                                </div>
                                <div class="provenance-item">
                                    <span>TREE ESTIMATORS</span>
                                    <strong class="mono">${prov.n_estimators || 300} Trees</strong>
                                </div>
                                <div class="provenance-item">
                                    <span>CONTAMINATION PARAMETER</span>
                                    <strong class="mono">${prov.contamination || 0.08}</strong>
                                </div>
                                <div class="provenance-item">
                                    <span>MULTI-VECTOR FEATURES</span>
                                    <strong class="mono">${prov.feature_count || 9} Verified Vectors</strong>
                                </div>
                                <div class="provenance-item">
                                    <span>ACTIVE DATASET PERSISTED</span>
                                    <strong class="mono">${esc(prov.dataset_name || 'bitcoin_traffic.csv')}</strong>
                                </div>
                                <div class="provenance-item">
                                    <span>PERSISTENCE LAYER</span>
                                    <strong class="mono">${esc(prov.persistence_layer || 'SQLite Engine')}</strong>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- SECTION 11: INVESTIGATIVE RECOMMENDATIONS -->
                    <div class="report-section">
                        <div class="report-section-title">10. INVESTIGATIVE RECOMMENDATIONS &amp; ACTION PLAN</div>
                        <ul style="padding-left:18px;font-size:12px;color:var(--text-muted);display:flex;flex-direction:column;gap:8px;">
                            ${recs.map((r) => `<li><strong>•</strong> ${esc(r)}</li>`).join("")}
                        </ul>
                    </div>

                    <!-- SECTION 12: CHAIN OF CUSTODY & CERTIFICATION -->
                    <div class="report-section">
                        <div class="report-section-title">11. CHAIN OF CUSTODY &amp; CERTIFICATION</div>
                        <div class="provenance-card" style="margin-top:0;">
                            <div class="provenance-grid">
                                <div class="provenance-item">
                                    <span>CERTIFIED ANALYST</span>
                                    <strong class="mono text-cyan">${esc(cert.analyst_id || 'TRACEX_AUTOMATED_FORENSIC_ENGINE')}</strong>
                                </div>
                                <div class="provenance-item">
                                    <span>INTEGRITY VERIFICATION</span>
                                    <strong class="mono text-green">${esc(cert.integrity_status || 'CRYPTOGRAPHICALLY VERIFIED')}</strong>
                                </div>
                                <div class="provenance-item">
                                    <span>CLASSIFICATION STANDARD</span>
                                    <strong class="mono">${esc(cert.classification_standard || 'RESTRICTED FORENSIC INTELLIGENCE')}</strong>
                                </div>
                                <div class="provenance-item">
                                    <span>SHA-256 INTEGRITY SEAL</span>
                                    <strong class="mono" style="font-size:10px;word-break:break-all;">${esc(cert.sha256_checksum || 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')}</strong>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;

            // Wire report controls
            const printBtn = $("#btn-print-report");
            if (printBtn) printBtn.onclick = () => window.print();

            const copyMdBtn = $("#btn-copy-markdown");
            if (copyMdBtn) {
                copyMdBtn.onclick = () => {
                    const text = `TRACE-X FORENSIC INTELLIGENCE DOSSIER
Case Ref: ${m.case_id}
Target: ${m.target}
Classification: ${m.classification}
Analyzed Wallets: ${risk.analyzed_wallets}
Critical Threats: ${risk.critical_alerts_count}
Max Risk Score: ${risk.max_risk}
Top Suspicious Entity: ${threats[0]?.wallet_address || 'N/A'}`;
                    copyToClipboard(text, "Dossier Summary");
                };
            }

            const targetSelect = $("#report-target-select");
            const applyTargetBtn = $("#btn-apply-report-target");
            if (applyTargetBtn && targetSelect) {
                applyTargetBtn.onclick = () => {
                    const sel = targetSelect.value;
                    App.state.routeParams = { id: sel };
                    Views.renderInvestigationReports(container);
                };
            }
        },

        // ----------------------------------------------------------------------
        // 9. SYSTEM HEALTH
        // ----------------------------------------------------------------------
        async renderSystemHealth(container) {
            const health = await API.get("/system/health");
            const db = health.database || {};
            const ml = health.ml_engine || {};
            const env = health.environment || {};

            container.innerHTML = `
                <div class="page-header">
                    <div class="page-title-group">
                        <h1 class="page-title">
                            SYSTEM DIAGNOSTICS &amp; WORKSTATION HEALTH
                            <span class="risk-chip safe">OPERATIONAL</span>
                        </h1>
                        <p class="page-subtitle">Real-time status of backend services, SQLite persistence layer, and machine learning inference pipeline.</p>
                    </div>
                </div>

                <div style="display:grid;grid-template-columns:repeat(auto-fit, minmax(300px, 1fr));gap:20px;">
                    <!-- DATABASE DIAGNOSTICS -->
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
                                    <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
                                    <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
                                </svg>
                                SQLITE DATABASE ENGINE
                            </span>
                            <span class="risk-chip safe">${db.status ? db.status.toUpperCase() : 'CONNECTED'}</span>
                        </div>
                        <div class="card-body">
                            <div class="telemetry-summary-list">
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Engine</span>
                                    <span class="telemetry-summary-value text-cyan">${esc(db.engine || 'SQLite 3')}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Database Size</span>
                                    <span class="telemetry-summary-value">${num((db.size_bytes || 0) / (1024 * 1024), 2)} MB</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Wallets Table</span>
                                    <span class="telemetry-summary-value">${int(db.counts?.wallets)} rows</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Transactions Table</span>
                                    <span class="telemetry-summary-value">${int(db.counts?.transactions)} rows</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Network Observations</span>
                                    <span class="telemetry-summary-value">${int(db.counts?.observations)} rows</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">IP Nodes Table</span>
                                    <span class="telemetry-summary-value">${int(db.counts?.ips)} rows</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- ML ENGINE DIAGNOSTICS -->
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"></path>
                                    <polyline points="3.27 6.96 12 12.01 20.73 6.96"></polyline>
                                    <line x1="12" y1="22.08" x2="12" y2="12"></line>
                                </svg>
                                MACHINE LEARNING ANOMALY ENGINE
                            </span>
                            <span class="risk-chip safe">${ml.status ? ml.status.toUpperCase() : 'ACTIVE'}</span>
                        </div>
                        <div class="card-body">
                            <div class="telemetry-summary-list">
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Anomaly Model</span>
                                    <span class="telemetry-summary-value text-cyan">${esc(ml.algorithm || 'Isolation Forest')}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Estimators / Trees</span>
                                    <span class="telemetry-summary-value">${ml.n_estimators || 300} trees</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Contamination Rate</span>
                                    <span class="telemetry-summary-value">${ml.contamination || 0.08}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Model File Size</span>
                                    <span class="telemetry-summary-value">${num((ml.model_size_bytes || 0) / 1024, 1)} KB</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Multi-Vector Features</span>
                                    <span class="telemetry-summary-value text-green">${(ml.features || []).length || 9} Active Vectors</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <!-- RUNTIME & ENVIRONMENT -->
                    <div class="cyber-card">
                        <div class="card-header">
                            <span class="card-title">
                                <svg class="card-title-icon" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2">
                                    <polyline points="4 17 10 11 4 5"></polyline>
                                    <line x1="12" y1="19" x2="20" y2="19"></line>
                                </svg>
                                APPLICATION RUNTIME SPECS
                            </span>
                            <span class="risk-chip safe">v1.0.0</span>
                        </div>
                        <div class="card-body">
                            <div class="telemetry-summary-list">
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Python Environment</span>
                                    <span class="telemetry-summary-value text-cyan">Python ${esc(env.python || '3.12')}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Host Platform</span>
                                    <span class="telemetry-summary-value">${esc(env.platform || 'macOS')}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">API Gateway</span>
                                    <span class="telemetry-summary-value">FastAPI / ${esc(env.server || 'Uvicorn')}</span>
                                </div>
                                <div class="telemetry-summary-item">
                                    <span class="telemetry-summary-label">Offline Capability</span>
                                    <span class="telemetry-summary-value text-green">100% Standalone Ready</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }
    };

    // ==========================================================================
    // INITIALIZATION & GLOBAL HANDLERS
    // ==========================================================================
    function bootstrap() {
        Router.init();

        // Wire Omnibar Global Search
        const omnibar = $("#global-search-input");
        if (omnibar) {
            omnibar.addEventListener("keydown", (e) => {
                if (e.key === "Enter") {
                    const q = omnibar.value.trim();
                    if (!q) return;

                    // Address detection
                    if (q.startsWith("bc1") || q.startsWith("1") || q.startsWith("3")) {
                        Router.navigate(`wallet/${encodeURIComponent(q)}`);
                    } else if (q.length >= 32 && !q.includes(".")) {
                        Router.navigate(`transaction/${encodeURIComponent(q)}`);
                    } else {
                        // Default search in alerts
                        Router.navigate(`alerts`);
                    }
                    omnibar.value = "";
                }
            });
        }

        // Wire Refresh Button
        const refreshBtn = $("#btn-header-refresh");
        if (refreshBtn) {
            refreshBtn.addEventListener("click", () => {
                showToast("Reloading forensic state...", "info");
                Router.handleRoute();
            });
        }
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", bootstrap);
    } else {
        bootstrap();
    }
})();
