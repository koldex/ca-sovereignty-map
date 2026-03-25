/**
 * CAmap Nordics — Shared map logic
 * Adapted from mxmap's map-shared.js (David Huser)
 */
'use strict';

// Three confidence tiers per category:
//   high  (conf ≥75%)  — strong colour
//   medium(50–74%)   — lighter shade
//   low   (<50%)     — pale tint of the same hue (NOT grey — municipality IS classified)
// 'unknown' and 'no-data' use neutral greys only.
const COLOR_SCHEMES = {
  default: {
    'us-controlled': { high: '#e74c3c', medium: '#f1948a', low: '#fadbd8' },
    'eu-controlled': { high: '#3498db', medium: '#85c1e9', low: '#d6eaf8' },
    'nordic':        { high: '#2ecc71', medium: '#82e0aa', low: '#d5f5e3' },
    'allied':        { high: '#f39c12', medium: '#f8c471', low: '#fdebd0' },
    'unknown':       { high: '#aaaaaa', medium: '#cccccc', low: '#eeeeee' },
    lake: '#89B3D6',
  },
  colorblind: {
    'us-controlled': { high: '#d55e00', medium: '#f0b27a', low: '#fad7c3' },
    'eu-controlled': { high: '#0072b2', medium: '#7fb3d8', low: '#cde5f5' },
    'nordic':        { high: '#009e73', medium: '#7fceab', low: '#c8edd8' },
    'allied':        { high: '#e69f00', medium: '#f2ce7e', low: '#faecc5' },
    'unknown':       { high: '#aaaaaa', medium: '#cccccc', low: '#eeeeee' },
    lake: '#c4afff',
  },
};

let activeColorScheme = 'default';

function getMuniColor(muni) {
  const scheme = COLOR_SCHEMES[activeColorScheme];
  const category = muni.category || 'unknown';
  const conf = muni.classification_confidence || 0;
  const colors = scheme[category] || scheme['unknown'];
  if (conf >= 75) return colors.high;
  if (conf >= 50) return colors.medium;
  return colors.low;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const JURISDICTION_LABELS = {
  'us': 'US-controlled',
  'eu': 'EU-controlled',
  'nordic': 'Nordic',
  'allied': 'Allied',
  'other': 'Unknown',
};

const RISK_LABELS = {
  'critical': '🔴 Critical',
  'high':     '🟠 High',
  'medium':   '🟡 Medium',
  'low':      '🟢 Low',
  'minimal':  '✅ Minimal',
};

function jurisdictionBadgeHtml(jurisdiction) {
  return `<span class="badge badge-${jurisdiction}">${JURISDICTION_LABELS[jurisdiction] || jurisdiction}</span>`;
}

function buildPopup(muni) {
  const conf = muni.classification_confidence || 0;
  const domain = muni.domain || '';
  const chain = muni.cert_chain || [];
  const signals = muni.classification_signals || [];
  const caaRecords = muni.caa_records || [];
  const tlsInfo = muni.tls_info || {};

  const chainHtml = chain.length > 0
    ? `<div class="chain-container">${chain.map(c => {
        return `<div class="chain-node">
          <span class="chain-type">${escapeHtml(c.cert_type)}</span>
          <span class="chain-issuer">${escapeHtml(c.issuer_cn || c.issuer_org || '–')}</span>
          <span class="chain-country">${escapeHtml(c.issuer_country || '')}</span>
        </div>`;
      }).join('')}</div>`
    : '<em class="text-muted text-small">No certificate chain</em>';

  const signalsHtml = signals.length > 0
    ? signals.slice(0, 3).map(s =>
        `<div class="text-small text-muted">${escapeHtml(s.kind)}: ${escapeHtml(s.ca_name)} (${s.weight.toFixed(2)})</div>`
      ).join('') : '';

  // Error / context notice
  const errCat = muni.error_category || '';
  const contextHtml = (() => {
    if (errCat === 'http_only')
      return `<div class="popup-notice notice-http">⚠ HTTP only — no TLS certificate on this domain. The municipality's site does not use HTTPS.</div>`;
    if (errCat === 'shared_hosting' || muni.cert_mismatch)
      return `<div class="popup-notice notice-shared">ℹ Shared hosting — certificate belongs to the hosting platform, not the municipality domain. CA shown is the platform's CA.</div>`;
    if (muni.shared_hosting && !muni.cert_mismatch)
      return `<div class="popup-notice notice-shared">ℹ Shared hosting — this municipality shares the same TLS certificate with ${muni.shared_cert_fingerprint ? 'others on the same server' : 'other municipalities'}.</div>`;
    if (errCat === 'timeout')
      return `<div class="popup-notice notice-unknown">⚠ Connection timed out — server did not respond on port 443 within 15 s.</div>`;
    if (errCat === 'ssl_error' || errCat === 'ssl_mismatch')
      return `<div class="popup-notice notice-unknown">⚠ TLS error — ${escapeHtml(muni.error || 'SSL negotiation failed')}.</div>`;
    return '';
  })();

  return `<div>
    <div class="popup-header">
      <div>
        <div class="popup-name">${escapeHtml(muni.name)}</div>
        <div class="popup-country">${escapeHtml(muni.country)}${muni.region ? ' · ' + escapeHtml(muni.region) : ''}</div>
      </div>
      ${jurisdictionBadgeHtml(muni.jurisdiction || 'other')}
    </div>
    ${domain ? `<div class="popup-domain"><a href="https://${escapeHtml(domain)}" target="_blank" rel="noopener">${escapeHtml(domain)}</a></div>` : ''}
    ${contextHtml}
    ${muni.category !== 'unknown' || muni.cert_mismatch || muni.shared_hosting ? `
    <div class="popup-section">
      <div class="popup-section-title">Certificate Authority</div>
      <strong>${escapeHtml(muni.primary_ca || '–')}</strong>
      ${muni.ca_country ? `<span class="text-muted"> · ${escapeHtml(muni.ca_country)}</span>` : ''}
      ${muni.ca_owner ? `<div class="text-small text-muted">${escapeHtml(muni.ca_owner)}</div>` : ''}
    </div>` : ''}
    ${chain.length > 0 ? `<div class="popup-section">
      <div class="popup-section-title">Certificate Chain</div>
      ${chainHtml}
    </div>` : ''}
    ${caaRecords.length > 0 ? `<div class="popup-section">
      <div class="popup-section-title">DNS CAA Records</div>
      <code class="text-small">${caaRecords.map(escapeHtml).join(', ')}</code>
    </div>` : ''}
    ${muni.category !== 'unknown' ? `<div class="popup-section">
      <div class="popup-section-title">Risk Level</div>
      ${RISK_LABELS[muni.risk_level] || muni.risk_level || '–'}
    </div>` : ''}
    ${signalsHtml ? `<div class="popup-section">
      <div class="popup-section-title">Classification Signals</div>
      ${signalsHtml}
    </div>` : ''}
    ${conf > 0 ? `<div class="mt-2">
      <div class="text-small text-muted">
        Confidence: ${conf.toFixed(1)}%
        ${tlsInfo.tls_version ? ' · ' + escapeHtml(tlsInfo.tls_version) : ''}
        ${tlsInfo.verification === 'OK' ? ' · ✓ Verified' : ''}
        ${muni.scanned_domain ? ' · scanned: ' + escapeHtml(muni.scanned_domain) : ''}
      </div>
      <div class="confidence-bar">
        <div class="confidence-fill" style="width: ${conf}%"></div>
      </div>
    </div>` : ''}
  </div>`;
}

function initMap(containerId) {
  const map = L.map(containerId, {
    center: [63.0, 18.0], zoom: 5,
    minZoom: 4, maxZoom: 14,
    renderer: L.canvas(),
    scrollWheelZoom: true, touchZoom: true,
    maxBounds: L.latLngBounds(L.latLng(54.0, 3.0), L.latLng(72.0, 32.0)),
  });
  L.tileLayer('https://{s}.basemaps.cartocdn.com/light_nolabels/{z}/{x}/{y}{r}.png', {
    attribution: '© <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> © <a href="https://carto.com/">CARTO</a>',
    subdomains: 'abcd', maxZoom: 19,
  }).addTo(map);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/light_only_labels/{z}/{x}/{y}{r}.png', {
    subdomains: 'abcd', maxZoom: 19, pane: 'shadowPane',
  }).addTo(map);
  return map;
}

async function fetchMapData(url) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to load ${url}: ${resp.status} ${resp.statusText}`);
  return resp.json();
}

async function fetchTopoJson(url) {
  const resp = await fetch(url);
  if (!resp.ok) throw new Error(`Failed to load ${url}: ${resp.status} ${resp.statusText}`);
  return resp.json();
}

function addLegend(map) {
  const legend = L.control({ position: 'bottomright' });
  legend.onAdd = function () {
    const scheme = COLOR_SCHEMES[activeColorScheme];
    const div = L.DomUtil.create('div', 'legend');
    div.innerHTML = `
      <div class="legend-title">CA Jurisdiction</div>
      ${[
        ['us-controlled', 'US-controlled (CLOUD Act)'],
        ['eu-controlled', 'EU-controlled'],
        ['nordic',        'Nordic'],
        ['allied',        'Allied country'],
        ['unknown',       'Unknown / No HTTPS'],
      ].map(([cat, label]) => `
        <div class="legend-item">
          <div class="legend-swatch" style="background:${scheme[cat].high}"></div>
          <span>${label}</span>
        </div>`).join('')}
      <div class="legend-item">
        <div class="legend-swatch" style="background:#c0cad4"></div>
        <span>No domain data</span>
      </div>
      <div class="mt-2 text-small text-muted">
        <label style="cursor:pointer">
          <input type="checkbox" id="cb-mode" onchange="toggleColorblind(this.checked)">
          Colorblind mode
        </label>
      </div>`;
    L.DomEvent.disableClickPropagation(div);
    return div;
  };
  legend.addTo(map);
  return legend;
}

function toggleColorblind(enabled) {
  activeColorScheme = enabled ? 'colorblind' : 'default';
  if (typeof window.onColorSchemeChange === 'function') {
    window.onColorSchemeChange(activeColorScheme);
  }
}

function setupInfoBar(containerId) {
  const bar = document.getElementById(containerId);
  if (!bar) return;
  bar.innerHTML = `<div id="info-bar-content">
    <span class="text-muted text-small">Click a municipality to see details</span>
  </div>`;
}

function updateInfoBar(muni) {
  const content = document.getElementById('info-bar-content');
  if (!content) return;
  content.innerHTML = `
    <div>
      <div class="muni-name">${escapeHtml(muni.name)} <span class="text-muted">(${escapeHtml(muni.country)})</span></div>
      <div class="muni-domain">${escapeHtml(muni.domain || '–')}</div>
    </div>
    <div>
      ${jurisdictionBadgeHtml(muni.jurisdiction || 'other')}
      <span class="text-small text-muted" style="margin-left:6px">${escapeHtml(muni.primary_ca || '–')}</span>
    </div>
    <div class="text-small text-muted">
      Confidence: ${(muni.classification_confidence || 0).toFixed(1)}%
    </div>`;
}
