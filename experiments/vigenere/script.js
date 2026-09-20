/* ============================================================
   Vigenère Cipher Simulator with Cryptanalysis — script.js
   TE Computer Engineering · CSS TH ISE · Group 1
   ============================================================ */

// ────────────────────────────────────────────────
// 1. CORE CIPHER FUNCTIONS
// ────────────────────────────────────────────────

/**
 * Sanitise the key: uppercase, keep only A-Z.
 * Returns null if no alphabetic characters remain.
 */
function sanitiseKey(raw) {
    if (!raw) return null;
    const cleaned = raw.replace(/[^A-Za-z]/g, '').toUpperCase();
    return cleaned.length === 0 ? null : cleaned;
}

/**
 * Encrypt plaintext with a Vigenère key.
 * Returns { ciphertext, keyStream, steps[] }.
 *
 * Rules (from supplied spec):
 *  - Only A-Z/a-z are shifted; non-alpha pass through unchanged.
 *  - Non-alpha characters do NOT advance the key pointer.
 *  - Original case is preserved.
 *  - Key repeats cyclically.
 */
function vigenereEncrypt(plaintext, rawKey) {
    const key = sanitiseKey(rawKey);
    if (!key) return { error: 'Invalid key — must contain at least one letter (A-Z).' };

    let ciphertext = '';
    let keyStream  = '';
    const steps    = [];
    let keyIdx     = 0;          // index into cleaned key
    let alphaIdx   = 0;          // index among alphabetic chars only

    for (let i = 0; i < plaintext.length; i++) {
        const ch = plaintext[i];
        if (/[A-Za-z]/.test(ch)) {
            const isUpper = ch === ch.toUpperCase();
            const P       = ch.toUpperCase().charCodeAt(0) - 65;               // 0-25
            const kChar   = key[keyIdx % key.length];
            const K       = kChar.charCodeAt(0) - 65;                          // 0-25
            const C       = (P + K) % 26;
            const outChar = isUpper
                            ? String.fromCharCode(C + 65)
                            : String.fromCharCode(C + 97);

            steps.push({
                index:  alphaIdx,
                plain:  ch,
                pVal:   P,
                keyChar: kChar,
                kVal:   K,
                calc:   `(${P} + ${K}) mod 26 = ${C}`,
                cipher: outChar
            });

            ciphertext += outChar;
            keyStream  += isUpper ? kChar : kChar.toLowerCase();
            keyIdx++;
            alphaIdx++;
        } else {
            ciphertext += ch;
            keyStream  += ch;          // space / punctuation echoed
        }
    }

    return { ciphertext, keyStream, steps };
}

/**
 * Decrypt ciphertext with a Vigenère key.
 * Returns { plaintext, keyStream, steps[] }.
 *
 * Pi = ((Ci − Ki) mod 26 + 26) mod 26
 */
function vigenereDecrypt(ciphertext, rawKey) {
    const key = sanitiseKey(rawKey);
    if (!key) return { error: 'Invalid key — must contain at least one letter (A-Z).' };

    let plaintext  = '';
    let keyStream  = '';
    const steps    = [];
    let keyIdx     = 0;
    let alphaIdx   = 0;

    for (let i = 0; i < ciphertext.length; i++) {
        const ch = ciphertext[i];
        if (/[A-Za-z]/.test(ch)) {
            const isUpper = ch === ch.toUpperCase();
            const C       = ch.toUpperCase().charCodeAt(0) - 65;
            const kChar   = key[keyIdx % key.length];
            const K       = kChar.charCodeAt(0) - 65;
            const diff    = C - K;
            const P       = ((diff) % 26 + 26) % 26;
            const outChar = isUpper
                            ? String.fromCharCode(P + 65)
                            : String.fromCharCode(P + 97);

            steps.push({
                index:  alphaIdx,
                cipher: ch,
                cVal:   C,
                keyChar: kChar,
                kVal:   K,
                calc:   `(${C} - ${K}) mod 26 = (${diff} + 26) mod 26 = ${P}`,
                plain:  outChar
            });

            plaintext += outChar;
            keyStream += isUpper ? kChar : kChar.toLowerCase();
            keyIdx++;
            alphaIdx++;
        } else {
            plaintext += ch;
            keyStream += ch;
        }
    }

    return { plaintext, keyStream, steps };
}

// ────────────────────────────────────────────────
// 2. FREQUENCY ANALYSIS
// ────────────────────────────────────────────────

/**
 * Count letter frequencies (A-Z only). Returns { counts[26], total }.
 */
function letterFrequency(text) {
    const counts = new Array(26).fill(0);
    let total = 0;
    for (const ch of text.toUpperCase()) {
        const code = ch.charCodeAt(0) - 65;
        if (code >= 0 && code < 26) {
            counts[code]++;
            total++;
        }
    }
    return { counts, total };
}

/**
 * Calculate percentage frequencies.
 */
function percentageFrequency(counts, total) {
    return counts.map(c => total === 0 ? 0 : (c / total) * 100);
}

// ────────────────────────────────────────────────
// 3. CHART RENDERING (pure canvas, no libraries)
// ────────────────────────────────────────────────

const LABELS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'.split('');

function drawBarChart(canvasId, title, datasets) {
    const canvas = document.getElementById(canvasId);
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const dpr = window.devicePixelRatio || 1;

    // Responsive sizing
    const rect = canvas.parentElement.getBoundingClientRect();
    const W = Math.floor(rect.width) || 600;
    const H = 320;
    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    // Layout constants
    const padL = 48, padR = 16, padT = 40, padB = 44;
    const chartW = W - padL - padR;
    const chartH = H - padT - padB;
    const barGroupW = chartW / 26;

    // Find max
    let maxVal = 1;
    for (const ds of datasets) {
        for (const v of ds.data) {
            if (v > maxVal) maxVal = v;
        }
    }
    maxVal = Math.ceil(maxVal * 1.15) || 1;

    // Background
    ctx.fillStyle = '#fafbfd';
    ctx.fillRect(0, 0, W, H);

    // Grid
    const gridLines = 5;
    ctx.strokeStyle = '#e2e6ea';
    ctx.lineWidth = 1;
    ctx.font = '11px "Inter", sans-serif';
    ctx.fillStyle = '#6b7280';
    ctx.textAlign = 'right';
    ctx.textBaseline = 'middle';
    for (let i = 0; i <= gridLines; i++) {
        const y = padT + chartH - (i / gridLines) * chartH;
        const val = ((i / gridLines) * maxVal).toFixed(0);
        ctx.beginPath();
        ctx.moveTo(padL, y);
        ctx.lineTo(W - padR, y);
        ctx.stroke();
        ctx.fillText(val, padL - 6, y);
    }

    // Title
    ctx.fillStyle = '#1e293b';
    ctx.font = 'bold 13px "Inter", sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText(title, W / 2, 18);

    // Bars
    const numDs = datasets.length;
    const gap = 2;
    const barW = Math.max(2, (barGroupW - gap * 2) / numDs);

    for (let d = 0; d < numDs; d++) {
        const ds = datasets[d];
        ctx.fillStyle = ds.color;
        for (let i = 0; i < 26; i++) {
            const x = padL + i * barGroupW + gap + d * barW;
            const h = (ds.data[i] / maxVal) * chartH;
            const y = padT + chartH - h;
            ctx.fillRect(x, y, barW - 1, h);
        }
    }

    // X labels
    ctx.fillStyle = '#374151';
    ctx.font = '10px "Inter", sans-serif';
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    for (let i = 0; i < 26; i++) {
        const x = padL + i * barGroupW + barGroupW / 2;
        ctx.fillText(LABELS[i], x, padT + chartH + 6);
    }

    // Legend
    if (numDs > 1) {
        ctx.font = '11px "Inter", sans-serif';
        ctx.textAlign = 'left';
        let lx = padL + 4;
        const ly = H - 10;
        for (const ds of datasets) {
            ctx.fillStyle = ds.color;
            ctx.fillRect(lx, ly - 8, 12, 10);
            ctx.fillStyle = '#374151';
            ctx.fillText(ds.label, lx + 16, ly);
            lx += ctx.measureText(ds.label).width + 36;
        }
    }
}

// ────────────────────────────────────────────────
// 4. TABULA RECTA BUILDER
// ────────────────────────────────────────────────

function buildTabulaRecta() {
    const container = document.getElementById('tabula-recta');
    if (!container) return;
    const table = document.createElement('table');
    table.className = 'tabula-recta-table';

    // Header row
    const headerRow = document.createElement('tr');
    const cornerTh = document.createElement('th');
    cornerTh.textContent = '';
    cornerTh.className = 'tabula-corner';
    headerRow.appendChild(cornerTh);
    for (let c = 0; c < 26; c++) {
        const th = document.createElement('th');
        th.textContent = LABELS[c];
        th.className = 'tabula-col-header';
        th.id = `tabula-col-${c}`;
        headerRow.appendChild(th);
    }
    table.appendChild(headerRow);

    // Body rows
    for (let r = 0; r < 26; r++) {
        const tr = document.createElement('tr');
        const rowTh = document.createElement('th');
        rowTh.textContent = LABELS[r];
        rowTh.className = 'tabula-row-header';
        rowTh.id = `tabula-row-${r}`;
        tr.appendChild(rowTh);
        for (let c = 0; c < 26; c++) {
            const td = document.createElement('td');
            td.textContent = LABELS[(r + c) % 26];
            td.id = `tabula-${r}-${c}`;
            tr.appendChild(td);
        }
        table.appendChild(tr);
    }

    container.innerHTML = '';
    container.appendChild(table);
}

function highlightTabulaRecta(pChar, kChar) {
    // Clear previous highlights
    document.querySelectorAll('.tabula-recta-table .highlight-cell, .tabula-recta-table .highlight-header').forEach(el => {
        el.classList.remove('highlight-cell', 'highlight-header', 'highlight-row', 'highlight-col');
    });
    if (!pChar || !kChar) return;
    const r = kChar.toUpperCase().charCodeAt(0) - 65;
    const c = pChar.toUpperCase().charCodeAt(0) - 65;
    if (r < 0 || r > 25 || c < 0 || c > 25) return;

    const rowH = document.getElementById(`tabula-row-${r}`);
    const colH = document.getElementById(`tabula-col-${c}`);
    const cell = document.getElementById(`tabula-${r}-${c}`);
    if (rowH) rowH.classList.add('highlight-header', 'highlight-row');
    if (colH) colH.classList.add('highlight-header', 'highlight-col');
    if (cell) cell.classList.add('highlight-cell');
}

// ────────────────────────────────────────────────
// 5. KEY STREAM VISUALIZATION
// ────────────────────────────────────────────────

function renderKeyStream(containerId, topLabel, topText, bottomLabel, bottomText, midLabel, midText) {
    const el = document.getElementById(containerId);
    if (!el) return;

    // Build aligned rows
    let html = '<div class="key-stream-vis">';
    html += `<div class="ks-row"><span class="ks-label">${topLabel}:</span>`;
    for (let i = 0; i < topText.length; i++) {
        const ch = topText[i];
        const isAlpha = /[A-Za-z]/.test(ch);
        html += `<span class="ks-char ${isAlpha ? 'ks-alpha' : 'ks-non-alpha'}">${ch === ' ' ? '&nbsp;' : ch}</span>`;
    }
    html += '</div>';

    html += `<div class="ks-row"><span class="ks-label">${midLabel}:</span>`;
    for (let i = 0; i < midText.length; i++) {
        const ch = midText[i];
        const isAlpha = /[A-Za-z]/.test(ch);
        html += `<span class="ks-char ${isAlpha ? 'ks-key' : 'ks-non-alpha'}">${ch === ' ' ? '&nbsp;' : ch}</span>`;
    }
    html += '</div>';

    html += `<div class="ks-row"><span class="ks-label">${bottomLabel}:</span>`;
    for (let i = 0; i < bottomText.length; i++) {
        const ch = bottomText[i];
        const isAlpha = /[A-Za-z]/.test(ch);
        html += `<span class="ks-char ${isAlpha ? 'ks-result' : 'ks-non-alpha'}">${ch === ' ' ? '&nbsp;' : ch}</span>`;
    }
    html += '</div></div>';

    el.innerHTML = html;
}

// ────────────────────────────────────────────────
// 6. STEP-BY-STEP TABLE BUILDER
// ────────────────────────────────────────────────

function buildEncryptTable(steps) {
    if (!steps || steps.length === 0) return '<p class="muted">No alphabetic characters to process.</p>';
    let html = '<table class="step-table"><thead><tr>';
    html += '<th>Index</th><th>Plain</th><th>P (value)</th><th>Key</th><th>K (value)</th><th>Calculation</th><th>Cipher</th>';
    html += '</tr></thead><tbody>';
    for (const s of steps) {
        html += `<tr>
            <td>${s.index}</td>
            <td class="char-cell">${s.plain}</td>
            <td>${s.pVal}</td>
            <td class="char-cell">${s.keyChar}</td>
            <td>${s.kVal}</td>
            <td class="calc-cell">${s.calc}</td>
            <td class="char-cell result-cell">${s.cipher}</td>
        </tr>`;
    }
    html += '</tbody></table>';
    return html;
}

function buildDecryptTable(steps) {
    if (!steps || steps.length === 0) return '<p class="muted">No alphabetic characters to process.</p>';
    let html = '<table class="step-table"><thead><tr>';
    html += '<th>Index</th><th>Cipher</th><th>C (value)</th><th>Key</th><th>K (value)</th><th>Calculation</th><th>Plain</th>';
    html += '</tr></thead><tbody>';
    for (const s of steps) {
        html += `<tr>
            <td>${s.index}</td>
            <td class="char-cell">${s.cipher}</td>
            <td>${s.cVal}</td>
            <td class="char-cell">${s.keyChar}</td>
            <td>${s.kVal}</td>
            <td class="calc-cell">${s.calc}</td>
            <td class="char-cell result-cell">${s.plain}</td>
        </tr>`;
    }
    html += '</tbody></table>';
    return html;
}

// ────────────────────────────────────────────────
// 7. UI EVENT HANDLERS
// ────────────────────────────────────────────────

/* ── Section Navigation ── */
let currentSection = 'section-intro';

function showSection(id) {
    document.querySelectorAll('.lab-section').forEach(s => s.classList.remove('active'));
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    const sec = document.getElementById(id);
    if (sec) {
        sec.classList.add('active');
        sec.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
    const nav = document.querySelector(`.nav-link[data-section="${id}"]`);
    if (nav) nav.classList.add('active');
    currentSection = id;
}

/* ── Encryption ── */
function handleEncrypt() {
    const plaintext = document.getElementById('enc-plaintext').value;
    const rawKey    = document.getElementById('enc-key').value;
    const resultDiv = document.getElementById('enc-result');
    const stepsDiv  = document.getElementById('enc-steps');
    const ksDiv     = document.getElementById('enc-keystream');

    if (!plaintext) {
        resultDiv.innerHTML = '<p class="error-msg">Please enter plaintext.</p>';
        stepsDiv.innerHTML = '';
        ksDiv.innerHTML = '';
        return;
    }

    const result = vigenereEncrypt(plaintext, rawKey);
    if (result.error) {
        resultDiv.innerHTML = `<p class="error-msg">${result.error}</p>`;
        stepsDiv.innerHTML = '';
        ksDiv.innerHTML = '';
        return;
    }

    resultDiv.innerHTML = `
        <div class="output-block">
            <label>Ciphertext:</label>
            <div class="output-text" id="enc-output-text">${result.ciphertext}</div>
            <button class="btn btn-sm" onclick="copyText('enc-output-text')" title="Copy ciphertext">Copy</button>
        </div>`;

    renderKeyStream(ksDiv.id, 'Plaintext', plaintext, 'Key', result.keyStream, 'Ciphertext', result.ciphertext);
    stepsDiv.innerHTML = '<h4>Step-by-Step Encryption Trace</h4>' + buildEncryptTable(result.steps);

    // Easter egg: subtle message when key is LEMON
    const cleanKey = sanitiseKey(rawKey);
    if (cleanKey === 'LEMON') {
        const easterDiv = document.getElementById('enc-easter');
        if (easterDiv) {
            easterDiv.innerHTML = '<span class="easter-egg" title="le chiffre indéchiffrable — so they thought for 300 years!">🍋</span>';
            setTimeout(() => { easterDiv.innerHTML = ''; }, 4000);
        }
    }
}

function handleDecrypt() {
    const ciphertext = document.getElementById('dec-ciphertext').value;
    const rawKey     = document.getElementById('dec-key').value;
    const resultDiv  = document.getElementById('dec-result');
    const stepsDiv   = document.getElementById('dec-steps');
    const ksDiv      = document.getElementById('dec-keystream');

    if (!ciphertext) {
        resultDiv.innerHTML = '<p class="error-msg">Please enter ciphertext.</p>';
        stepsDiv.innerHTML = '';
        ksDiv.innerHTML = '';
        return;
    }

    const result = vigenereDecrypt(ciphertext, rawKey);
    if (result.error) {
        resultDiv.innerHTML = `<p class="error-msg">${result.error}</p>`;
        stepsDiv.innerHTML = '';
        ksDiv.innerHTML = '';
        return;
    }

    resultDiv.innerHTML = `
        <div class="output-block">
            <label>Plaintext:</label>
            <div class="output-text" id="dec-output-text">${result.plaintext}</div>
            <button class="btn btn-sm" onclick="copyText('dec-output-text')" title="Copy plaintext">Copy</button>
        </div>`;

    renderKeyStream(ksDiv.id, 'Ciphertext', ciphertext, 'Key', result.keyStream, 'Plaintext', result.plaintext);
    stepsDiv.innerHTML = '<h4>Step-by-Step Decryption Trace</h4>' + buildDecryptTable(result.steps);
}

/* ── Load Example ── */
function loadEncExample() {
    document.getElementById('enc-plaintext').value = 'ATTACK AT DAWN';
    document.getElementById('enc-key').value = 'LEMON';
    handleEncrypt();
}

function loadDecExample() {
    document.getElementById('dec-ciphertext').value = 'LXFOPV EF RNHR';
    document.getElementById('dec-key').value = 'LEMON';
    handleDecrypt();
}

/* ── Clear ── */
function clearEncrypt() {
    document.getElementById('enc-plaintext').value = '';
    document.getElementById('enc-key').value = '';
    document.getElementById('enc-result').innerHTML = '';
    document.getElementById('enc-steps').innerHTML = '';
    document.getElementById('enc-keystream').innerHTML = '';
}

function clearDecrypt() {
    document.getElementById('dec-ciphertext').value = '';
    document.getElementById('dec-key').value = '';
    document.getElementById('dec-result').innerHTML = '';
    document.getElementById('dec-steps').innerHTML = '';
    document.getElementById('dec-keystream').innerHTML = '';
}

/* ── Copy ── */
function copyText(elId) {
    const el = document.getElementById(elId);
    if (!el) return;
    navigator.clipboard.writeText(el.textContent).then(() => {
        const btn = el.parentElement.querySelector('.btn-sm');
        if (btn) {
            const orig = btn.textContent;
            btn.textContent = 'Copied!';
            setTimeout(() => { btn.textContent = orig; }, 1200);
        }
    });
}

// ────────────────────────────────────────────────
// 8. CRYPTANALYSIS UI
// ────────────────────────────────────────────────

function handleCryptanalysis() {
    const plaintext  = document.getElementById('ca-plaintext').value;
    const rawKey     = document.getElementById('ca-key').value;
    const resultDiv  = document.getElementById('ca-result');
    const tableDiv   = document.getElementById('ca-freq-table');

    if (!plaintext) {
        resultDiv.innerHTML = '<p class="error-msg">Please enter plaintext.</p>';
        tableDiv.innerHTML = '';
        return;
    }
    const encResult = vigenereEncrypt(plaintext, rawKey);
    if (encResult.error) {
        resultDiv.innerHTML = `<p class="error-msg">${encResult.error}</p>`;
        tableDiv.innerHTML = '';
        return;
    }

    const ciphertext = encResult.ciphertext;
    resultDiv.innerHTML = `
        <div class="output-block">
            <label>Ciphertext produced:</label>
            <div class="output-text">${ciphertext}</div>
        </div>`;

    const ptFreq = letterFrequency(plaintext);
    const ctFreq = letterFrequency(ciphertext);
    const ptPct  = percentageFrequency(ptFreq.counts, ptFreq.total);
    const ctPct  = percentageFrequency(ctFreq.counts, ctFreq.total);

    // Frequency table
    let tbl = '<table class="freq-table"><thead><tr><th>Letter</th><th>PT Count</th><th>PT %</th><th>CT Count</th><th>CT %</th></tr></thead><tbody>';
    for (let i = 0; i < 26; i++) {
        tbl += `<tr>
            <td>${LABELS[i]}</td>
            <td>${ptFreq.counts[i]}</td>
            <td>${ptPct[i].toFixed(1)}</td>
            <td>${ctFreq.counts[i]}</td>
            <td>${ctPct[i].toFixed(1)}</td>
        </tr>`;
    }
    tbl += `</tbody><tfoot><tr><td><strong>Total</strong></td><td><strong>${ptFreq.total}</strong></td><td></td><td><strong>${ctFreq.total}</strong></td><td></td></tr></tfoot></table>`;
    tableDiv.innerHTML = tbl;

    // Draw three charts
    drawBarChart('chart-pt', 'Plaintext Letter Frequency', [
        { data: ptFreq.counts, color: '#3b82f6', label: 'Plaintext' }
    ]);
    drawBarChart('chart-ct', 'Ciphertext Letter Frequency', [
        { data: ctFreq.counts, color: '#ef4444', label: 'Ciphertext' }
    ]);
    drawBarChart('chart-compare', 'Plaintext vs Ciphertext Frequency', [
        { data: ptFreq.counts, color: '#3b82f6', label: 'Plaintext' },
        { data: ctFreq.counts, color: '#ef4444', label: 'Ciphertext' }
    ]);

    // Observation text
    const observeDiv = document.getElementById('ca-observation');
    if (observeDiv) {
        // Count how many distinct letters appear in PT vs CT
        const ptDistinct = ptFreq.counts.filter(c => c > 0).length;
        const ctDistinct = ctFreq.counts.filter(c => c > 0).length;
        observeDiv.innerHTML = `
        <div class="observation-card">
            <h4>Observation</h4>
            <ul>
                <li>The plaintext uses <strong>${ptDistinct}</strong> distinct letter(s); the ciphertext uses <strong>${ctDistinct}</strong>.</li>
                <li>In a monoalphabetic cipher (e.g., Caesar), the ciphertext distribution is simply a shifted copy of the plaintext distribution.
                    Single-letter frequency analysis can therefore break it.</li>
                <li>The Vigenère cipher uses <strong>multiple shifts</strong> (one per key letter), so the same plaintext letter can map to
                    <strong>different</strong> ciphertext letters. This flattens the ciphertext distribution and makes single-letter frequency analysis
                    less effective.</li>
                <li>However, because the key <strong>repeats</strong>, structural patterns remain. Methods such as <em>Kasiski examination</em> and
                    the <em>index of coincidence</em> can exploit this repetition to determine the key length and eventually break the cipher.</li>
            </ul>
        </div>`;
    }
}

function loadCaExample() {
    document.getElementById('ca-plaintext').value = 'ATTACKATDAWN';
    document.getElementById('ca-key').value = 'LEMON';
    handleCryptanalysis();
}

function clearCryptanalysis() {
    document.getElementById('ca-plaintext').value = '';
    document.getElementById('ca-key').value = '';
    document.getElementById('ca-result').innerHTML = '';
    document.getElementById('ca-freq-table').innerHTML = '';
    document.getElementById('ca-observation').innerHTML = '';
    ['chart-pt', 'chart-ct', 'chart-compare'].forEach(id => {
        const c = document.getElementById(id);
        if (c) { const ctx = c.getContext('2d'); ctx.clearRect(0, 0, c.width, c.height); }
    });
}

// ────────────────────────────────────────────────
// 9. STEP-BY-STEP SIMULATION (animated)
// ────────────────────────────────────────────────

let simState = null;

function startSimulation() {
    const plaintext = document.getElementById('sim-plaintext').value;
    const rawKey    = document.getElementById('sim-key').value;
    const mode      = document.querySelector('input[name="sim-mode"]:checked').value;
    const outputDiv = document.getElementById('sim-output');

    const key = sanitiseKey(rawKey);
    if (!key) {
        outputDiv.innerHTML = '<p class="error-msg">Invalid key — must contain at least one letter (A-Z).</p>';
        return;
    }
    if (!plaintext) {
        outputDiv.innerHTML = '<p class="error-msg">Please enter text to process.</p>';
        return;
    }

    simState = {
        input: plaintext,
        key: key,
        mode: mode,
        pos: 0,
        keyIdx: 0,
        alphaIdx: 0,
        output: '',
        rows: [],
        running: true
    };

    outputDiv.innerHTML = `
        <div class="sim-progress">
            <div class="sim-input-display"><strong>Input:</strong> <span id="sim-input-chars"></span></div>
            <div class="sim-output-display"><strong>Output:</strong> <span id="sim-output-chars"></span></div>
            <div id="sim-current-step" class="sim-current-step"></div>
            <div id="sim-table-container"></div>
        </div>`;

    renderSimInputChars();
    advanceSimulation();
}

function renderSimInputChars() {
    if (!simState) return;
    const el = document.getElementById('sim-input-chars');
    if (!el) return;
    let html = '';
    for (let i = 0; i < simState.input.length; i++) {
        const cls = i < simState.pos ? 'sim-done' : (i === simState.pos ? 'sim-active' : '');
        const ch = simState.input[i] === ' ' ? '&nbsp;' : simState.input[i];
        html += `<span class="sim-char ${cls}">${ch}</span>`;
    }
    el.innerHTML = html;
}

function advanceSimulation() {
    if (!simState || !simState.running) return;
    if (simState.pos >= simState.input.length) {
        simState.running = false;
        const stepEl = document.getElementById('sim-current-step');
        if (stepEl) stepEl.innerHTML = '<p class="success-msg">✓ Simulation complete!</p>';
        document.getElementById('sim-next-btn').disabled = true;
        // Highlight tabula recta clear
        highlightTabulaRecta(null, null);
        return;
    }

    const ch = simState.input[simState.pos];
    const stepEl = document.getElementById('sim-current-step');

    if (/[A-Za-z]/.test(ch)) {
        const isUpper = ch === ch.toUpperCase();
        const val = ch.toUpperCase().charCodeAt(0) - 65;
        const kChar = simState.key[simState.keyIdx % simState.key.length];
        const kVal = kChar.charCodeAt(0) - 65;

        let outVal, calc, outChar;
        if (simState.mode === 'encrypt') {
            outVal = (val + kVal) % 26;
            calc = `(${val} + ${kVal}) mod 26 = ${outVal}`;
            outChar = isUpper ? String.fromCharCode(outVal + 65) : String.fromCharCode(outVal + 97);
        } else {
            const diff = val - kVal;
            outVal = ((diff) % 26 + 26) % 26;
            calc = `(${val} - ${kVal}) mod 26 = (${diff} + 26) mod 26 = ${outVal}`;
            outChar = isUpper ? String.fromCharCode(outVal + 65) : String.fromCharCode(outVal + 97);
        }

        simState.rows.push({
            index: simState.alphaIdx,
            inputChar: ch,
            inputVal: val,
            keyChar: kChar,
            keyVal: kVal,
            calc: calc,
            outputChar: outChar,
            outputVal: outVal
        });

        simState.output += outChar;
        simState.keyIdx++;
        simState.alphaIdx++;

        if (stepEl) {
            stepEl.innerHTML = `
                <div class="sim-step-detail">
                    <strong>Step ${simState.alphaIdx}:</strong>
                    '${ch}' (${val}) ${simState.mode === 'encrypt' ? '+' : '−'} '${kChar}' (${kVal}) → ${calc} → '${outChar}'
                </div>`;
        }

        // Highlight tabula recta
        if (simState.mode === 'encrypt') {
            highlightTabulaRecta(ch, kChar);
        } else {
            highlightTabulaRecta(outChar, kChar);
        }
    } else {
        simState.output += ch;
        if (stepEl) {
            stepEl.innerHTML = `<div class="sim-step-detail"><strong>Non-alphabetic character:</strong> '${ch === ' ' ? '(space)' : ch}' — passed through, key not advanced.</div>`;
        }
        highlightTabulaRecta(null, null);
    }

    simState.pos++;
    renderSimInputChars();

    // Update output chars
    const outEl = document.getElementById('sim-output-chars');
    if (outEl) {
        let html = '';
        for (const c of simState.output) {
            const disp = c === ' ' ? '&nbsp;' : c;
            html += `<span class="sim-char sim-done">${disp}</span>`;
        }
        outEl.innerHTML = html;
    }

    // Update table
    const tblContainer = document.getElementById('sim-table-container');
    if (tblContainer && simState.rows.length > 0) {
        const isEnc = simState.mode === 'encrypt';
        let html = '<table class="step-table"><thead><tr>';
        html += `<th>Index</th><th>${isEnc ? 'Plain' : 'Cipher'}</th><th>Value</th><th>Key</th><th>K(val)</th><th>Calculation</th><th>${isEnc ? 'Cipher' : 'Plain'}</th>`;
        html += '</tr></thead><tbody>';
        for (const r of simState.rows) {
            html += `<tr><td>${r.index}</td><td class="char-cell">${r.inputChar}</td><td>${r.inputVal}</td><td class="char-cell">${r.keyChar}</td><td>${r.keyVal}</td><td class="calc-cell">${r.calc}</td><td class="char-cell result-cell">${r.outputChar}</td></tr>`;
        }
        html += '</tbody></table>';
        tblContainer.innerHTML = html;
    }
}

function loadSimExample() {
    document.getElementById('sim-plaintext').value = 'ATTACK AT DAWN';
    document.getElementById('sim-key').value = 'LEMON';
    document.querySelector('input[name="sim-mode"][value="encrypt"]').checked = true;
}

function resetSimulation() {
    simState = null;
    document.getElementById('sim-output').innerHTML = '<p class="muted">Click "Start" to begin the step-by-step simulation.</p>';
    document.getElementById('sim-next-btn').disabled = false;
    highlightTabulaRecta(null, null);
}

function autoRunSimulation() {
    if (!simState || !simState.running) {
        startSimulation();
    }
    if (!simState || !simState.running) return;

    const interval = setInterval(() => {
        if (!simState || !simState.running) {
            clearInterval(interval);
            return;
        }
        advanceSimulation();
    }, 500);
}

// ────────────────────────────────────────────────
// 10. QUIZ
// ────────────────────────────────────────────────

const quizQuestions = [
    {
        q: "The Vigenère cipher is classified as which type of cipher?",
        options: [
            "Monoalphabetic substitution cipher",
            "Polyalphabetic substitution cipher",
            "Transposition cipher",
            "Stream cipher"
        ],
        correct: 1,
        explanation: "The Vigenère cipher uses multiple substitution alphabets (one per key letter), making it a polyalphabetic substitution cipher."
    },
    {
        q: "In the standard Vigenère mapping, what numeric value corresponds to the letter 'A'?",
        options: [
            "1",
            "0",
            "26",
            "65"
        ],
        correct: 1,
        explanation: "The standard convention is A=0, B=1, …, Z=25."
    },
    {
        q: "What is the Vigenère encryption formula?",
        options: [
            "Cᵢ = (Pᵢ − Kᵢ) mod 26",
            "Cᵢ = (Pᵢ × Kᵢ) mod 26",
            "Cᵢ = (Pᵢ + Kᵢ) mod 26",
            "Cᵢ = (Pᵢ + Kᵢ) mod 25"
        ],
        correct: 2,
        explanation: "Encryption adds the plaintext value and key value modulo 26: Cᵢ = (Pᵢ + Kᵢ) mod 26."
    },
    {
        q: "What is the Vigenère decryption formula?",
        options: [
            "Pᵢ = (Cᵢ + Kᵢ) mod 26",
            "Pᵢ = (Cᵢ − Kᵢ + 26) mod 26",
            "Pᵢ = (Cᵢ × Kᵢ) mod 26",
            "Pᵢ = (Cᵢ / Kᵢ) mod 26"
        ],
        correct: 1,
        explanation: "Decryption subtracts the key value and adds 26 before taking mod 26 to handle negative values: Pᵢ = (Cᵢ − Kᵢ + 26) mod 26."
    },
    {
        q: "If the keyword is shorter than the plaintext, what happens?",
        options: [
            "The remaining plaintext is left unencrypted",
            "The keyword is padded with 'A'",
            "The keyword repeats cyclically from the beginning",
            "An error occurs"
        ],
        correct: 2,
        explanation: "The key repeats cyclically: the key index advances as i mod m, where m is the key length."
    },
    {
        q: "If the Vigenère key consists of a single letter, the cipher reduces to which cipher?",
        options: [
            "Playfair cipher",
            "Rail fence cipher",
            "Caesar cipher",
            "One-time pad"
        ],
        correct: 2,
        explanation: "A single-letter key means every plaintext letter is shifted by the same amount, which is exactly a Caesar cipher."
    },
    {
        q: "Why is single-letter frequency analysis less effective against the Vigenère cipher compared to a Caesar cipher?",
        options: [
            "Vigenère uses a transposition step",
            "The same plaintext letter can be encrypted to different ciphertext letters depending on the key letter",
            "Vigenère removes all vowels before encryption",
            "Vigenère uses a non-linear transformation"
        ],
        correct: 1,
        explanation: "Because different key letters provide different shifts, the same plaintext letter maps to different ciphertext letters at different positions, flattening the frequency distribution."
    },
    {
        q: "How does key length affect the security of the Vigenère cipher?",
        options: [
            "Longer keys make the cipher weaker",
            "Key length has no effect on security",
            "Longer keys increase the number of possible keys and make frequency analysis harder",
            "Only keys of exactly 5 letters are secure"
        ],
        correct: 2,
        explanation: "For key length m, there are 26ᵐ possible keys. A longer key means each plaintext letter is encrypted with a larger variety of shifts, making frequency analysis harder."
    },
    {
        q: "What method did Friedrich Kasiski publish in 1863 for breaking the Vigenère cipher?",
        options: [
            "Brute-force all 26 keys",
            "Analysing repeated sequences in the ciphertext to determine key length",
            "Using a dictionary attack on the key",
            "Reversing the tabula recta"
        ],
        correct: 1,
        explanation: "Kasiski examination finds repeated sequences in the ciphertext. The distances between repetitions are likely multiples of the key length, revealing it."
    },
    {
        q: "In the Vigenère cipher, when a non-alphabetic character (e.g., space or punctuation) is encountered in the plaintext, what happens?",
        options: [
            "It is removed from the output",
            "It is replaced with 'X'",
            "It passes through unchanged and the key pointer does NOT advance",
            "It passes through unchanged and the key pointer advances"
        ],
        correct: 2,
        explanation: "Non-alphabetic characters are preserved in their original position without any transformation, and the key pointer is not advanced."
    }
];

let quizState = { answered: [], score: 0, submitted: false };
let shuffledQuiz = [];

function shuffleArray(arr) {
    const a = [...arr];
    for (let i = a.length - 1; i > 0; i--) {
        const j = Math.floor(Math.random() * (i + 1));
        [a[i], a[j]] = [a[j], a[i]];
    }
    return a;
}

function initQuiz() {
    // Shuffle question order; for each question shuffle options while tracking correct answer
    shuffledQuiz = shuffleArray(quizQuestions.map((q, origIdx) => {
        const optionIndices = [0, 1, 2, 3];
        const shuffledIndices = shuffleArray(optionIndices);
        return {
            ...q,
            origIdx,
            shuffledOptions: shuffledIndices.map(i => q.options[i]),
            correctShuffled: shuffledIndices.indexOf(q.correct)
        };
    }));

    quizState = { answered: new Array(shuffledQuiz.length).fill(null), score: 0, submitted: false };
    renderQuiz();
}

function renderQuiz() {
    const container = document.getElementById('quiz-questions');
    if (!container) return;
    let html = '';
    shuffledQuiz.forEach((q, qi) => {
        const answered = quizState.answered[qi] !== null;
        const isCorrect = answered && quizState.answered[qi] === q.correctShuffled;
        html += `<div class="quiz-question ${answered ? (isCorrect ? 'quiz-correct' : 'quiz-wrong') : ''}" id="quiz-q-${qi}">
            <p class="quiz-q-text"><strong>Q${qi + 1}.</strong> ${q.q}</p>
            <div class="quiz-options">`;
        q.shuffledOptions.forEach((opt, oi) => {
            const selected = quizState.answered[qi] === oi;
            const disabled = answered ? 'disabled' : '';
            const optClass = answered
                ? (oi === q.correctShuffled ? 'correct-opt' : (selected ? 'wrong-opt' : ''))
                : '';
            html += `<label class="quiz-option ${optClass} ${selected ? 'selected' : ''}">
                <input type="radio" name="quiz-${qi}" value="${oi}" ${disabled} ${selected ? 'checked' : ''}
                    onchange="answerQuiz(${qi}, ${oi})">
                <span>${opt}</span>
            </label>`;
        });
        html += '</div>';
        if (answered) {
            html += `<div class="quiz-explanation">
                <strong>${isCorrect ? '✓ Correct!' : '✗ Incorrect.'}</strong> ${q.explanation}
            </div>`;
        }
        html += '</div>';
    });
    container.innerHTML = html;
    updateQuizScore();
}

function answerQuiz(qi, oi) {
    if (quizState.answered[qi] !== null) return;
    quizState.answered[qi] = oi;
    if (oi === shuffledQuiz[qi].correctShuffled) quizState.score++;
    renderQuiz();
}

function updateQuizScore() {
    const el = document.getElementById('quiz-score');
    if (!el) return;
    const total = shuffledQuiz.length;
    const answeredCount = quizState.answered.filter(a => a !== null).length;
    if (answeredCount === 0) {
        el.innerHTML = `<span class="muted">Answer all ${total} questions to see your score.</span>`;
    } else if (answeredCount < total) {
        el.innerHTML = `Answered: ${answeredCount}/${total} &middot; Current Score: ${quizState.score}/${answeredCount}`;
    } else {
        const pct = ((quizState.score / total) * 100).toFixed(0);
        el.innerHTML = `<strong>Final Score: ${quizState.score}/${total} (${pct}%)</strong>`;
    }
}

function resetQuiz() {
    initQuiz();
}

// ────────────────────────────────────────────────
// 11. INTERNAL TESTS (console + on-page)
// ────────────────────────────────────────────────

function runTests() {
    const results = [];
    let pass = 0, fail = 0;

    function assert(name, condition, detail) {
        if (condition) {
            results.push({ name, status: 'PASS', detail });
            pass++;
        } else {
            results.push({ name, status: 'FAIL', detail });
            fail++;
        }
    }

    // TC-ENC-01
    let r = vigenereEncrypt('ATTACKATDAWN', 'LEMON');
    assert('TC-ENC-01', r.ciphertext === 'LXFOPVEFRNHR',
        `Expected LXFOPVEFRNHR, got ${r.ciphertext}`);

    // TC-ENC-01b (with spaces)
    r = vigenereEncrypt('ATTACK AT DAWN', 'LEMON');
    assert('TC-ENC-01b (spaces)', r.ciphertext === 'LXFOPV EF RNHR',
        `Expected "LXFOPV EF RNHR", got "${r.ciphertext}"`);

    // TC-ENC-02 (mixed case + punctuation)
    r = vigenereEncrypt('Att ack at Dawn!', 'lemon');
    assert('TC-ENC-02 case/punct', r.ciphertext === 'Lxf opv ef Rnhr!',
        `Expected "Lxf opv ef Rnhr!", got "${r.ciphertext}"`);

    // TC-ENC-03 (key = A → Caesar shift 0)
    r = vigenereEncrypt('HELLO', 'A');
    assert('TC-ENC-03 key=A', r.ciphertext === 'HELLO',
        `Expected HELLO, got ${r.ciphertext}`);

    // TC-ENC-04 (key longer than plaintext)
    r = vigenereEncrypt('CRYPTOGRAPHY', 'VERYLONGKEYWHICHISLONGERTHANPLAINTEXT');
    // C(2)+V(21)=23=X, R(17)+E(4)=21=V, Y(24)+R(17)=41%26=15=P, P(15)+Y(24)=39%26=13=N,
    // T(19)+L(11)=30%26=4=E, O(14)+O(14)=28%26=2=C, G(6)+N(13)=19=T, R(17)+G(6)=23=X,
    // A(0)+K(10)=10=K, P(15)+E(4)=19=T, H(7)+Y(24)=31%26=5=F, Y(24)+W(22)=46%26=20=U
    assert('TC-ENC-04 long key', r.ciphertext === 'XVPNECTXKTFU',
        `Expected XVPNECTXKTFU, got ${r.ciphertext}`);

    // TC-DEC-01
    r = vigenereDecrypt('LXFOPVEFRNHR', 'LEMON');
    assert('TC-DEC-01', r.plaintext === 'ATTACKATDAWN',
        `Expected ATTACKATDAWN, got ${r.plaintext}`);

    // TC-DEC-01b (with spaces)
    r = vigenereDecrypt('LXFOPV EF RNHR', 'LEMON');
    assert('TC-DEC-01b (spaces)', r.plaintext === 'ATTACK AT DAWN',
        `Expected "ATTACK AT DAWN", got "${r.plaintext}"`);

    // TC-DEC-02 (mixed case + punctuation)
    r = vigenereDecrypt('Lxf opv ef Rnhr!', 'lemon');
    assert('TC-DEC-02 case/punct', r.plaintext === 'Att ack at Dawn!',
        `Expected "Att ack at Dawn!", got "${r.plaintext}"`);

    // TC-DEC-03 (key = A)
    r = vigenereDecrypt('HELLO', 'A');
    assert('TC-DEC-03 key=A', r.plaintext === 'HELLO',
        `Expected HELLO, got ${r.plaintext}`);

    // TC-DEC-04 (long key)
    r = vigenereDecrypt('XVPNECTXKTFU', 'VERYLONGKEYWHICHISLONGERTHANPLAINTEXT');
    assert('TC-DEC-04 long key', r.plaintext === 'CRYPTOGRAPHY',
        `Expected CRYPTOGRAPHY, got ${r.plaintext}`);

    // Edge: empty key
    r = vigenereEncrypt('HELLO', '');
    assert('TC-EDGE-01 empty key', r.error !== undefined, `Should error on empty key`);

    // Edge: key with only symbols
    r = vigenereEncrypt('HELLO', '123!@#');
    assert('TC-EDGE-02 symbol key', r.error !== undefined, `Should error on symbol-only key`);

    // Edge: key with mixed chars
    r = vigenereEncrypt('HELLO', 'L3M*N');
    assert('TC-EDGE-03 mixed key', r.ciphertext !== undefined && r.error === undefined,
        `Key "L3M*N" should be sanitised to "LMN" — got ct: ${r.ciphertext}`);

    // Edge: empty plaintext
    r = vigenereEncrypt('', 'KEY');
    assert('TC-EDGE-04 empty pt', r.ciphertext === '', `Empty pt → empty ct`);

    // Inverse property: decrypt(encrypt(P,K),K) = P
    const testPairs = [
        ['Hello, World!', 'SECRET'],
        ['The Quick Brown Fox Jumps Over 123 Lazy Dogs!!!', 'CIPHER'],
        ['AAAAAAAAAA', 'Z'],
        ['abcdefghijklmnopqrstuvwxyz', 'KEY'],
        ['A', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'],
        ['Test 123... @@@ spaces!!!', 'vIgEnErE']
    ];
    testPairs.forEach(([pt, k], idx) => {
        const enc = vigenereEncrypt(pt, k);
        const dec = vigenereDecrypt(enc.ciphertext, k);
        assert(`TC-INV-${idx + 1}`, dec.plaintext === pt,
            `Inverse failed for "${pt}" / "${k}": enc="${enc.ciphertext}", dec="${dec.plaintext}"`);
    });

    // Frequency validation for ATTACKATDAWN / LEMON
    const ptFreq = letterFrequency('ATTACKATDAWN');
    const expectedPt = [4,0,1,1,0,0,0,0,0,0,1,0,0,1,0,0,0,0,0,3,0,0,1,0,0,0];
    const ptMatch = expectedPt.every((v, i) => ptFreq.counts[i] === v);
    assert('TC-FREQ-PT', ptMatch, `PT freq mismatch: ${JSON.stringify(ptFreq.counts)}`);

    const ctFreq = letterFrequency('LXFOPVEFRNHR');
    const expectedCt = [0,0,0,0,1,2,0,1,0,0,0,1,0,1,1,1,0,2,0,0,0,1,0,1,0,0];
    const ctMatch = expectedCt.every((v, i) => ctFreq.counts[i] === v);
    assert('TC-FREQ-CT', ctMatch, `CT freq mismatch: ${JSON.stringify(ctFreq.counts)}`);

    // Negative mod decryption: F(5) - L(11) = -6, should give T(19)
    // This is tested implicitly via TC-DEC-01, but let's be explicit
    r = vigenereDecrypt('F', 'L');
    assert('TC-NEG-MOD', r.plaintext === 'U',
        `F(5)-L(11)=-6 → (−6+26)%26=20=U, got ${r.plaintext}`);
    // Actually re-check: F=5, L=11, (5-11+26)%26 = 20 = U. The document example is within
    // a longer text context. Let's verify the specific step from the spec:
    // In LXFOPV, the 3rd letter F: key letter at position 2 is M(12). (5-12+26)%26 = 19 = T. ✓
    r = vigenereDecrypt('F', 'M');
    assert('TC-NEG-MOD-2', r.plaintext === 'T',
        `F(5)-M(12)=-7 → (−7+26)%26=19=T, got ${r.plaintext}`);

    // Display results
    const testDiv = document.getElementById('test-results');
    if (testDiv) {
        let html = `<p><strong>Results:</strong> ${pass} passed, ${fail} failed, ${pass + fail} total</p>`;
        html += '<table class="test-table"><thead><tr><th>Test</th><th>Status</th><th>Detail</th></tr></thead><tbody>';
        for (const t of results) {
            const cls = t.status === 'PASS' ? 'test-pass' : 'test-fail';
            html += `<tr class="${cls}"><td>${t.name}</td><td>${t.status}</td><td>${t.detail}</td></tr>`;
        }
        html += '</tbody></table>';
        testDiv.innerHTML = html;
    }

    // Console output
    console.log(`%c[TEST] ${pass} passed, ${fail} failed`, fail === 0 ? 'color:green' : 'color:red');
    results.forEach(t => {
        console.log(`  ${t.status === 'PASS' ? '✓' : '✗'} ${t.name}: ${t.detail}`);
    });

    return { pass, fail, results };
}

// ────────────────────────────────────────────────
// 12. INITIALISATION
// ────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    // Build tabula recta
    buildTabulaRecta();

    // Initialize quiz
    initQuiz();

    // Set up navigation
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const section = link.getAttribute('data-section');
            if (section) showSection(section);
        });
    });

    // Show first section
    showSection('section-intro');

    // Run tests automatically on load (console only, results visible in test section)
    runTests();

    // Resize handler for charts
    window.addEventListener('resize', () => {
        // Re-draw charts if cryptanalysis was already run
        const caResult = document.getElementById('ca-result');
        if (caResult && caResult.innerHTML.trim() !== '') {
            handleCryptanalysis();
        }
    });

    // Easter egg: Konami-esque sequence with 'BELLASO'
    let easterBuffer = '';
    document.addEventListener('keydown', (e) => {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA') return;
        easterBuffer += e.key.toUpperCase();
        if (easterBuffer.length > 20) easterBuffer = easterBuffer.slice(-20);
        if (easterBuffer.includes('KASISKI')) {
            const el = document.getElementById('easter-kasiski');
            if (el) {
                el.classList.add('show');
                setTimeout(() => el.classList.remove('show'), 5000);
            }
            easterBuffer = '';
        }
    });
});
