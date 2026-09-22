// Command-center dashboard client. Dependency-free vanilla JS: no build step,
// no third-party libraries. Renders only fields returned by /api/dashboard and
// /api/history -- both already redacted server-side by contracts.validate_event
// and dashboard.py. This file never calls GitHub and never fabricates a run
// URL; it only ever displays the `run_url` a snapshot already supplies.
(function () {
  "use strict";

  var REFRESH_INTERVAL_MS = 10000;

  var state = {
    snapshot: null,
    selectedRunnerId: null,
    historyFilters: { runner_id: "", repository: "", workflow_run_id: "", outcome: "", received_after: "", received_before: "" },
    historyEvents: [],
    historyPage: 1,
    historyHasNext: false,
    autoRefresh: true,
    lastUpdatedAt: null,
    refreshInFlight: false,
  };

  function badgeClass(kind, value) {
    if (kind === "liveness") return value === "online" ? "online" : "offline";
    if (kind === "activity") return value === "running" ? "running" : "idle";
    if (kind === "outcome") {
      if (value === "succeeded") return "succeeded";
      if (value === "failed") return "failed";
      if (value === "cancelled") return "cancelled";
      return "running";
    }
    return "idle";
  }

  function badge(label, kind, value) {
    return '<span class="badge ' + badgeClass(kind, value) + '">' + escapeHtml(label) + "</span>";
  }

  // Job status badges must be driven by `liveness` first: an offline job is
  // never "healthy" green, regardless of its last-known state or outcome.
  // Offline liveness always outranks activity/outcome for this decision, the
  // same priority order the rest of the dashboard uses for progress_unreported.
  function jobStatusBadge(job) {
    if (job.liveness === "offline") {
      return '<span class="badge offline">' + escapeHtml(job.offline_reason || "offline") + "</span>";
    }
    if (job.outcome === "succeeded") return '<span class="badge succeeded">succeeded</span>';
    if (job.outcome === "failed") return '<span class="badge failed">failed</span>';
    if (job.outcome === "cancelled") return '<span class="badge cancelled">cancelled</span>';
    return '<span class="badge running">' + escapeHtml(job.state) + "</span>";
  }

  function escapeHtml(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  function runnerAlias(runnerId) {
    return "runner-" + String(runnerId || "").slice(0, 8);
  }

  function actionsLink(runUrl) {
    if (!runUrl) return "";
    return '<a class="action-row" href="' + escapeHtml(runUrl) + '" target="_blank" rel="noreferrer">Open Actions run &#8599;</a>';
  }

  function phaseRow(stageId, phase) {
    var pct = phase.determinate && phase.total > 0 ? Math.round((phase.completed / phase.total) * 100) : null;
    var fillClass = phase.state === "failed" ? "failed" : phase.state === "completed" ? "done" : "";
    var caption = phase.determinate
      ? phase.completed + " / " + phase.total + " " + phase.unit_label
      : "indeterminate";
    // v1's progress schema has no dedicated safe/unsafe/skipped fields; show
    // only what the event actually carries (completed/total/failed/pending)
    // rather than fabricate a derived count the sender never asserted.
    var breakdown = phase.failed > 0
      ? '<div class="phase-caption">failed/unsafe so far: ' + phase.failed + "</div>"
      : "";
    var phaseFallback = "";
    if (phase.fallback_group_count > 0 || phase.affected_test_count > 0) {
      phaseFallback =
        '<div class="phase-caption">fallback so far: ' + phase.fallback_group_count + " groups &middot; " +
        phase.affected_test_count + " tests</div>";
    }
    return (
      '<div class="phase-row">' +
      '<div class="phase-head"><span>' + escapeHtml(stageId) + "</span><span>" + escapeHtml(phase.state) + "</span></div>" +
      (pct === null
        ? '<div class="phase-caption">' + escapeHtml(caption) + "</div>"
        : '<div class="progress-track"><div class="progress-fill ' + fillClass + '" style="width:' + pct + '%"></div></div>' +
          '<div class="phase-caption">' + escapeHtml(caption) + " (" + pct + "%)</div>") +
      breakdown +
      phaseFallback +
      "</div>"
    );
  }

  function fallbackBox(fallback) {
    if (!fallback) {
      return '<div class="fact-box"><div class="fact-label">fallback</div><div class="fact-value">none reported</div></div>';
    }
    return (
      '<div class="fact-box fallback">' +
      '<div class="fact-label">fallback &rarr; ' + escapeHtml(fallback.target_stage_id) + "</div>" +
      '<div class="fact-value">' + fallback.completed_groups + " / " + fallback.total_groups + " groups</div>" +
      '<div class="phase-caption">' + fallback.fallback_group_count + " groups &middot; " + fallback.affected_test_count + " tests</div>" +
      "</div>"
    );
  }

  function jobTimeline(entries) {
    if (!entries.length) return '<p class="empty-note">No events recorded for this job yet.</p>';
    var items = entries
      .map(function (entry) {
        return (
          "<li><time>received " + escapeHtml(entry.received_at) + " &middot; occurred " + escapeHtml(entry.occurred_at) + "</time>" +
          "<div>" + escapeHtml(entry.summary) + "</div></li>"
        );
      })
      .join("");
    return '<ul class="timeline">' + items + "</ul>";
  }

  function currentJobPanel(runner) {
    var job = runner.current_job;
    if (!job) {
      return (
        '<div class="now-header"><div><h2>' + escapeHtml(runner.alias) + "</h2><p>No job seen from this runner yet.</p></div>" +
        badge(runner.liveness, "liveness", runner.liveness) +
        "</div>"
      );
    }
    var phaseIds = Object.keys(job.phases);
    var phasesHtml = phaseIds.length
      ? '<div class="phase-grid">' + phaseIds.map(function (id) { return phaseRow(id, job.phases[id]); }).join("") + "</div>"
      : '<p class="empty-note">No detailed phase progress reported for this job.</p>';
    var hint = job.progress_unreported
      ? '<div class="fact-box hint"><div class="fact-label">progress_unreported</div><div class="fact-value">heartbeat is fresh, no new progress yet</div></div>'
      : "";
    return (
      '<div class="now-header"><div><h2>' + escapeHtml(job.job_name) + "</h2><p>" + escapeHtml(runner.alias) +
      " &middot; last heartbeat " + escapeHtml(job.last_heartbeat_at || "unknown") + "</p></div>" +
      jobStatusBadge(job) +
      "</div>" +
      phasesHtml +
      '<div class="fact-strip">' +
      '<div class="fact-box"><div class="fact-label">job liveness</div><div class="fact-value">' + escapeHtml(job.liveness) + "</div></div>" +
      '<div class="fact-box"><div class="fact-label">state / outcome</div><div class="fact-value">' + escapeHtml(job.state) + (job.outcome ? " / " + escapeHtml(job.outcome) : "") + "</div></div>" +
      fallbackBox(job.fallback) +
      "</div>" +
      hint +
      actionsLink(job.run_url) +
      "<h3>Timeline</h3>" +
      jobTimeline(job.timeline)
    );
  }

  function runnerRailItem(runner) {
    var active = runner.runner_id === state.selectedRunnerId ? " active" : "";
    return (
      '<button class="rail-item' + active + '" data-runner-id="' + escapeHtml(runner.runner_id) + '">' +
      "<strong>" + escapeHtml(runner.alias) + "</strong>" +
      "<span>" + escapeHtml(runner.liveness) + " &middot; " + escapeHtml(runner.activity) + "</span>" +
      "</button>"
    );
  }

  function incidentsPanel(incidents) {
    if (!incidents.length) return '<p class="empty-note">No incidents recorded.</p>';
    return incidents
      .slice()
      .reverse()
      .map(function (incident) {
        return (
          '<div class="incident">' +
          badge(incident.active ? "open" : "closed", "liveness", incident.active ? "offline" : "online") +
          " <strong>" + escapeHtml(incident.resource_kind) + " " + escapeHtml(incident.condition) + "</strong>" +
          "<time>" + escapeHtml(incident.opened_at) + "</time>" +
          "</div>"
        );
      })
      .join("");
  }

  function eventFeedPanel(feed) {
    if (!feed.length) return '<p class="empty-note">No events yet.</p>';
    return feed
      .map(function (entry) {
        return (
          '<div class="feed-entry"><time>' + escapeHtml(entry.received_at) + "</time>" +
          "<div><strong>" + escapeHtml(entry.event_type) + "</strong> &middot; " + escapeHtml(entry.runner_alias) +
          (entry.job_name ? " &middot; " + escapeHtml(entry.job_name) : "") + "</div>" +
          "<div>" + escapeHtml(entry.summary) + "</div></div>"
        );
      })
      .join("");
  }

  function render() {
    var snapshot = state.snapshot;
    if (!snapshot) return;
    var allRunners = snapshot.runners || [];
    var runners = snapshot.active_runners || allRunners.filter(function (runner) { return runner.liveness === "online"; });
    if (!state.selectedRunnerId && runners.length) state.selectedRunnerId = runners[0].runner_id;
    var selected = runners.filter(function (r) { return r.runner_id === state.selectedRunnerId; })[0] || runners[0];

    var app = document.getElementById("app");
    app.innerHTML =
      '<div class="shell">' +
      "<h1>Runner Observability</h1>" +
      '<p class="subtitle">Command center &middot; generated ' + escapeHtml(snapshot.generated_at) + "</p>" +
      refreshControls() +
      degradedBanner(snapshot.health) +
      '<div class="command-layout">' +
      '<aside class="surface runner-rail"><div class="rail-title">Runners</div>' +
      runners.map(runnerRailItem).join("") +
      "</aside>" +
      '<section class="surface now-panel">' +
      (selected ? currentJobPanel(selected) : '<p class="empty-note">No runners have reported yet.</p>') +
      "</section>" +
      '<aside>' +
      '<div class="surface incident-panel"><h3>Incidents</h3>' + incidentsPanel(snapshot.incidents) + "</div>" +
      '<div class="surface feed-panel"><h3>Live event feed</h3>' + eventFeedPanel(snapshot.event_feed) + "</div>" +
      "</aside>" +
      "</div>" +
      historySection(allRunners) +
      "</div>";

    Array.prototype.forEach.call(app.querySelectorAll("[data-runner-id]"), function (el) {
      el.addEventListener("click", function () {
        state.selectedRunnerId = el.getAttribute("data-runner-id");
        render();
      });
    });

    var applyButton = document.getElementById("history-apply");
    if (applyButton) applyButton.addEventListener("click", applyHistoryFilters);
    var previousButton = document.getElementById("history-prev");
    if (previousButton) previousButton.addEventListener("click", function () {
      if (state.historyPage > 1) {
        state.historyPage -= 1;
        loadHistory();
      }
    });
    var nextButton = document.getElementById("history-next");
    if (nextButton) nextButton.addEventListener("click", function () {
      if (state.historyHasNext) {
        state.historyPage += 1;
        loadHistory();
      }
    });

    var refreshToggle = document.getElementById("refresh-toggle");
    if (refreshToggle) refreshToggle.addEventListener("click", toggleAutoRefresh);
  }

  function refreshControls() {
    var label = state.autoRefresh ? "Pause auto-refresh" : "Resume auto-refresh";
    var updated = state.lastUpdatedAt ? new Date(state.lastUpdatedAt).toLocaleTimeString() : "never";
    return (
      '<div class="refresh-controls">' +
      '<span class="refresh-status">Auto-refresh: <strong>' + (state.autoRefresh ? "on" : "paused") + "</strong></span>" +
      '<span id="last-updated">Last updated: ' + escapeHtml(updated) + "</span>" +
      '<button id="refresh-toggle" type="button">' + label + "</button>" +
      "</div>"
    );
  }

  function degradedBanner(health) {
    if (!health || !health.degraded) return "";
    var reasons = (health.reasons || []).map(escapeHtml).join(", ") || "unspecified";
    return '<div class="degraded-banner"><strong>Monitor is degraded.</strong> ' + reasons + "</div>";
  }

  function historySection(runners) {
    var filters = state.historyFilters;
    var runnerOptions = runners
      .map(function (r) {
        var selected = r.runner_id === filters.runner_id ? " selected" : "";
        return '<option value="' + escapeHtml(r.runner_id) + '"' + selected + ">" + escapeHtml(r.alias) + "</option>";
      })
      .join("");
    function outcomeOption(value, label) {
      return '<option value="' + value + '"' + (filters.outcome === value ? " selected" : "") + ">" + label + "</option>";
    }
    var rows = state.historyEvents
      .map(function (event) {
        var job = event.payload && event.payload.job;
        return (
          "<tr><td>" + escapeHtml(event.runner_alias || runnerAlias(event.runner_id)) + "</td>" +
          "<td>" + escapeHtml(event.received_at) + "</td>" +
          "<td>" + escapeHtml(event.event_type) + "</td>" +
          "<td>" + escapeHtml(job ? job.repository : "") + (job ? " #" + escapeHtml(job.workflow_run_id) : "") + "</td>" +
          "<td>" + escapeHtml(job ? job.job_name : "") + "</td>" +
          "<td>" + escapeHtml(event.payload && event.payload.outcome ? event.payload.outcome : "") + "</td>" +
          "<td>" + (job && job.run_url ? '<a href="' + escapeHtml(job.run_url) + '" target="_blank" rel="noreferrer">Actions run</a>' : "") + "</td></tr>"
        );
      })
      .join("");
    return (
      '<section class="surface history-section">' +
      '<h2>History (retained 7 days by received time)</h2>' +
      '<div class="filters">' +
      '<select id="history-runner"><option value="">All runners</option>' + runnerOptions + "</select>" +
      '<input id="history-repository" type="text" placeholder="repository (workflow)" value="' + escapeHtml(filters.repository) + '">' +
      '<input id="history-workflow-run" type="number" min="1" placeholder="workflow run id" value="' + escapeHtml(filters.workflow_run_id) + '">' +
      '<select id="history-outcome"><option value="">All outcomes</option>' +
      outcomeOption("succeeded", "succeeded") + outcomeOption("failed", "failed") + outcomeOption("cancelled", "cancelled") +
      "</select>" +
      '<label>since <input id="history-since" type="datetime-local" value="' + escapeHtml(isoToLocalDateTime(filters.received_after)) + '"></label>' +
      '<label>until <input id="history-until" type="datetime-local" value="' + escapeHtml(isoToLocalDateTime(filters.received_before)) + '"></label>' +
      '<button id="history-apply">Apply filters</button>' +
      "</div>" +
      '<table class="history-table"><thead><tr><th>runner</th><th>received</th><th>event</th><th>workflow</th><th>job</th><th>outcome</th><th>actions</th></tr></thead>' +
      "<tbody>" + (rows || '<tr><td colspan="7">No events match the current filters.</td></tr>') + "</tbody></table>" +
      '<div class="history-pagination"><button id="history-prev" type="button"' + (state.historyPage <= 1 ? " disabled" : "") + '>Newer</button>' +
      '<span class="history-page">Page ' + state.historyPage + '</span>' +
      '<button id="history-next" type="button"' + (!state.historyHasNext ? " disabled" : "") + '>Older</button></div>' +
      "</section>"
    );
  }

  function localDateTimeToIso(value) {
    if (!value) return "";
    var parsed = new Date(value);
    if (isNaN(parsed.getTime())) return "";
    return parsed.toISOString();
  }

  function isoToLocalDateTime(value) {
    if (!value) return "";
    var parsed = new Date(value);
    if (isNaN(parsed.getTime())) return "";
    function pad(number) { return String(number).padStart(2, "0"); }
    return parsed.getFullYear() + "-" + pad(parsed.getMonth() + 1) + "-" + pad(parsed.getDate()) +
      "T" + pad(parsed.getHours()) + ":" + pad(parsed.getMinutes());
  }

  function applyHistoryFilters() {
    state.historyFilters = {
      runner_id: document.getElementById("history-runner").value,
      repository: document.getElementById("history-repository").value.trim(),
      workflow_run_id: document.getElementById("history-workflow-run").value,
      outcome: document.getElementById("history-outcome").value,
      received_after: localDateTimeToIso(document.getElementById("history-since").value),
      received_before: localDateTimeToIso(document.getElementById("history-until").value),
    };
    state.historyPage = 1;
    loadHistory();
  }

  function loadDashboard() {
    return fetch("/api/dashboard", { cache: "no-store" })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        state.snapshot = data;
        state.lastUpdatedAt = new Date().toISOString();
        render();
      })
      .catch(function () {
        var app = document.getElementById("app");
        app.innerHTML = '<p class="empty-note">Unable to load the dashboard right now.</p>';
      });
  }

  function loadHistory() {
    var params = new URLSearchParams();
    var filters = state.historyFilters;
    if (filters.runner_id) params.set("runner_id", filters.runner_id);
    if (filters.repository) params.set("repository", filters.repository);
    if (filters.workflow_run_id) params.set("workflow_run_id", filters.workflow_run_id);
    if (filters.outcome) params.set("outcome", filters.outcome);
    if (filters.received_after) params.set("received_after", filters.received_after);
    if (filters.received_before) params.set("received_before", filters.received_before);
    params.set("page", String(state.historyPage));
    var query = params.toString();
    return fetch("/api/history" + (query ? "?" + query : ""), { cache: "no-store" })
      .then(function (response) { return response.json(); })
      .then(function (data) {
        state.historyEvents = data.events || [];
        state.historyPage = data.page || state.historyPage;
        state.historyHasNext = Boolean(data.has_next);
        render();
      })
      .catch(function () {
        state.historyEvents = [];
        state.historyHasNext = false;
      });
  }

  function refreshAll() {
    if (state.refreshInFlight) return Promise.resolve();
    state.refreshInFlight = true;
    return loadDashboard()
      .then(loadHistory)
      .then(function () {
        state.refreshInFlight = false;
      }, function (error) {
        state.refreshInFlight = false;
        throw error;
      });
  }

  function toggleAutoRefresh() {
    state.autoRefresh = !state.autoRefresh;
    render();
    if (state.autoRefresh && document.visibilityState === "visible") refreshAll();
  }

  function startAutoRefresh() {
    window.setInterval(function () {
      if (state.autoRefresh && document.visibilityState === "visible") refreshAll();
    }, REFRESH_INTERVAL_MS);
    document.addEventListener("visibilitychange", function () {
      if (state.autoRefresh && document.visibilityState === "visible") refreshAll();
    });
  }

  startAutoRefresh();
  refreshAll();
})();
