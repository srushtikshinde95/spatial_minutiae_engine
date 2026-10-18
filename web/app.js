/**
 * Forensic Latent Print Analysis Workstation (AFIS MK-4)
 * Client-Side Controller & Forensic Latent Minutiae Plotter
 * Features: Live User Enrollment & Rotation-Invariant Verification Mode
 */

document.addEventListener('DOMContentLoaded', () => {
  // DOM Elements - Main Inspector
  const selectTemplate = document.getElementById('select-template');
  const btnExecuteQuery = document.getElementById('btn-execute-query');
  const btnRunBenchmark = document.getElementById('btn-run-benchmark');
  const btnClearConsole = document.getElementById('btn-clear-console');
  
  const canvas = document.getElementById('latent-canvas');
  const ctx = canvas.getContext('2d');
  
  const crosshairInfo = document.getElementById('crosshair-info');
  const chX = document.getElementById('ch-x');
  const chY = document.getElementById('ch-y');
  const chType = document.getElementById('ch-type');

  // Spec labels
  const specId = document.getElementById('spec-id');
  const specPattern = document.getElementById('spec-pattern');
  const specMinutiae = document.getElementById('spec-minutiae');
  const specBytes = document.getElementById('spec-bytes');

  // Console & Metrics
  const consoleTerminal = document.getElementById('console-terminal');
  const benchTimerClock = document.getElementById('bench-timer-clock');
  const mTier1Hops = document.getElementById('m-tier1-hops');
  const mTier1Prune = document.getElementById('m-tier1-prune');
  const mTier1Time = document.getElementById('m-tier1-time');
  const mTier2Hops = document.getElementById('m-tier2-hops');
  const mTier2Pruned = document.getElementById('m-tier2-pruned');
  const mTier2Time = document.getElementById('m-tier2-time');
  const mTier3Edges = document.getElementById('m-tier3-edges');
  const mTier3Eval = document.getElementById('m-tier3-eval');
  const mTier3Time = document.getElementById('m-tier3-time');
  const mTotalTime = document.getElementById('m-total-time');
  const mRamFootprint = document.getElementById('m-ram-footprint');
  const mPerRecord = document.getElementById('m-per-record');

  const candidatesTbody = document.getElementById('candidates-tbody');

  // Toggles & View Selectors
  const toggleMinutiae = document.getElementById('toggle-minutiae');
  const toggleGraph = document.getElementById('toggle-graph');
  const toggleOrientation = document.getElementById('toggle-orientation');
  const toggleGrid = document.getElementById('toggle-grid');
  const viewButtons = document.querySelectorAll('.tool-btn[data-view]');

  // Enrollment Modal Elements
  const btnOpenEnroll = document.getElementById('btn-open-enroll');
  const enrollmentModal = document.getElementById('enrollment-modal');
  const btnCloseEnroll = document.getElementById('btn-close-enroll');
  const enrollCaseId = document.getElementById('enroll-case-id');
  const dropzone = document.getElementById('dropzone');
  const enrollFileInput = document.getElementById('enroll-file-input');
  const btnCommitEnrollment = document.getElementById('btn-commit-enrollment');
  const enrollCanvas = document.getElementById('enroll-canvas');
  const enrollCtx = enrollCanvas.getContext('2d');
  const metaPattern = document.getElementById('meta-pattern');
  const metaCount = document.getElementById('meta-count');
  const metaBreakdown = document.getElementById('meta-breakdown');
  const metaBytes = document.getElementById('meta-bytes');

  // Rotated Match Verification Modal Elements
  const btnOpenRotationMode = document.getElementById('btn-open-rotation-mode');
  const rotationModal = document.getElementById('rotation-modal');
  const btnCloseRotation = document.getElementById('btn-close-rotation');
  const rotSelectTemplate = document.getElementById('rot-select-template');
  const rotSlider = document.getElementById('rot-slider');
  const rotAngleVal = document.getElementById('rot-angle-val');
  const btnRunRotationTest = document.getElementById('btn-run-rotation-test');
  const presetButtons = document.querySelectorAll('.preset-btn');
  const rotOrigId = document.getElementById('rot-orig-id');
  const rotQueryId = document.getElementById('rot-query-id');
  const canvasSplitOrig = document.getElementById('canvas-split-orig');
  const canvasSplitRot = document.getElementById('canvas-split-rot');
  const canvasSplitConnector = document.getElementById('canvas-split-connector');
  const rotTermOutput = document.getElementById('rot-term-output');
  const rotStatTop = document.getElementById('rot-stat-top');
  const rotStatInj = document.getElementById('rot-stat-inj');
  const rotStatDet = document.getElementById('rot-stat-det');
  const rotStatRmse = document.getElementById('rot-stat-rmse');
  const rotStatLat = document.getElementById('rot-stat-lat');

  // Standard Dual Comparison Modal
  const comparisonModal = document.getElementById('comparison-modal');
  const btnCloseModal = document.getElementById('btn-close-modal');
  const cmpQueryId = document.getElementById('cmp-query-id');
  const cmpMatchId = document.getElementById('cmp-match-id');
  const cmpQueryCanvas = document.getElementById('cmp-query-canvas');
  const cmpMatchCanvas = document.getElementById('cmp-match-canvas');
  const cmpDiagnostics = document.getElementById('cmp-diagnostics');

  // Application State
  let currentView = 'enhanced';
  let activeTemplate = null;
  let cachedTemplates = [];
  let currentImage = new Image();
  let currentSkelImage = new Image();
  let imagesLoaded = false;
  let activeTelemetry = null;
  let stagedEnrollBase64 = null;

  const PATTERN_NAMES = ['CLASS 0 [ARCH]', 'CLASS 1 [LOOP]', 'CLASS 2 [WHORL]'];

  // Initialize Workstation
  initializeWorkstation();

  async function initializeWorkstation() {
    logConsole('[SYS_INIT] Connecting to C11 Forensic AFIS Engine Backend...', 'info');
    try {
      const res = await fetch('/api/templates');
      const data = await res.json();
      cachedTemplates = data.templates;

      populateTemplateDropdowns();

      logConsole(`[INDEX_READY] Loaded ${cachedTemplates.length} candidate templates from Kaggle SOCOFing database.`, 'info');
      if (cachedTemplates.length > 0) {
        loadTemplate(cachedTemplates[0].id);
      }
    } catch (err) {
      logConsole(`[ERROR] Backend connection failed: ${err.message}`, 'warn');
    }
  }

  function populateTemplateDropdowns() {
    selectTemplate.innerHTML = '';
    rotSelectTemplate.innerHTML = '';

    cachedTemplates.forEach(t => {
      const opt = document.createElement('option');
      opt.value = t.id;
      opt.textContent = `${t.id} (${PATTERN_NAMES[t.pattern_class] || 'CLASS ?'})`;
      selectTemplate.appendChild(opt);

      const optRot = opt.cloneNode(true);
      rotSelectTemplate.appendChild(optRot);
    });
  }

  async function loadTemplate(templateId) {
    try {
      const res = await fetch(`/api/template/${templateId}`);
      activeTemplate = await res.json();

      specId.textContent = activeTemplate.id;
      specPattern.textContent = PATTERN_NAMES[activeTemplate.pattern_class] || `CLASS ${activeTemplate.pattern_class}`;
      
      const endings = activeTemplate.minutiae.filter(m => m.type === 0).length;
      const bifurcs = activeTemplate.minutiae.filter(m => m.type === 1).length;
      specMinutiae.textContent = `${activeTemplate.minutiae.length} POINTS (${endings} END / ${bifurcs} BIF)`;

      const rawBytes = JSON.stringify(activeTemplate).length;
      specBytes.textContent = `${rawBytes} BYTES (< 1024 B)`;

      imagesLoaded = false;
      currentImage = new Image();
      currentSkelImage = new Image();

      let loadedCount = 0;
      const onImgLoad = () => {
        loadedCount++;
        if (loadedCount >= 2) {
          imagesLoaded = true;
          renderPlotter();
        }
      };

      currentImage.onload = onImgLoad;
      currentSkelImage.onload = onImgLoad;
      currentImage.src = `/images/${activeTemplate.id}.png`;
      currentSkelImage.src = `/images/${activeTemplate.id}_skel.png`;

      logConsole(`[TEMPLATE_LOAD] Case '${activeTemplate.id}' loaded into Latent Minutiae Plotter.`, 'info');
    } catch (err) {
      logConsole(`[ERROR] Failed to load template: ${err.message}`, 'warn');
    }
  }

  selectTemplate.addEventListener('change', () => {
    loadTemplate(selectTemplate.value);
  });

  viewButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      viewButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentView = btn.getAttribute('data-view');
      renderPlotter();
    });
  });

  [toggleMinutiae, toggleGraph, toggleOrientation, toggleGrid].forEach(toggle => {
    toggle.addEventListener('change', renderPlotter);
  });

  canvas.addEventListener('mousemove', (e) => {
    const rect = canvas.getBoundingClientRect();
    const scaleX = canvas.width / rect.width;
    const scaleY = canvas.height / rect.height;

    const mouseX = (e.clientX - rect.left) * scaleX;
    const mouseY = (e.clientY - rect.top) * scaleY;

    const imgX = (mouseX / canvas.width) * 288.0;
    const imgY = (mouseY / canvas.height) * 375.0;

    chX.textContent = Math.round(imgX);
    chY.textContent = Math.round(imgY);

    if (activeTemplate && activeTemplate.minutiae) {
      let nearestMin = null;
      let minDistSq = 144.0;
      activeTemplate.minutiae.forEach(m => {
        const dx = m.x - imgX;
        const dy = m.y - imgY;
        const distSq = dx * dx + dy * dy;
        if (distSq < minDistSq) {
          minDistSq = distSq;
          nearestMin = m;
        }
      });

      if (nearestMin) {
        chType.textContent = nearestMin.type === 0 ? 'RIDGE ENDING (RED)' : 'BIFURCATION (GREEN)';
        chType.className = nearestMin.type === 0 ? 'text-crimson' : 'text-emerald';
      } else {
        chType.textContent = 'NONE';
        chType.className = 'text-dim';
      }
    }
  });

  function renderPlotter() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    const W = canvas.width;
    const H = canvas.height;

    ctx.fillStyle = '#05070A';
    ctx.fillRect(0, 0, W, H);

    if (imagesLoaded) {
      const activeImg = (currentView === 'skeleton') ? currentSkelImage : currentImage;
      ctx.drawImage(activeImg, 0, 0, W, H);
    }

    if (toggleGrid.checked) {
      ctx.strokeStyle = 'rgba(0, 229, 255, 0.08)';
      ctx.lineWidth = 1;
      const stepX = W / 10;
      const stepY = H / 12;
      for (let x = 0; x <= W; x += stepX) {
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, H);
        ctx.stroke();
      }
      for (let y = 0; y <= H; y += stepY) {
        ctx.beginPath();
        ctx.moveTo(0, y);
        ctx.lineTo(W, y);
        ctx.stroke();
      }
    }

    if (!activeTemplate || !activeTemplate.minutiae) return;

    const scaleX = W / 288.0;
    const scaleY = H / 375.0;
    const points = activeTemplate.minutiae.map((m, idx) => ({
      idx,
      x: m.x * scaleX,
      y: m.y * scaleY,
      theta: m.theta,
      type: m.type,
      raw: m
    }));

    // Invariant Adjacency Graph Delaunay / K-NN Edges
    if (toggleGraph.checked && points.length > 1) {
      ctx.strokeStyle = 'rgba(0, 229, 255, 0.35)';
      ctx.lineWidth = 1.2;

      points.forEach(p1 => {
        const sorted = points
          .filter(p2 => p2.idx !== p1.idx)
          .map(p2 => {
            const dx = p2.x - p1.x;
            const dy = p2.y - p1.y;
            return { p: p2, d: Math.sqrt(dx * dx + dy * dy) };
          })
          .sort((a, b) => a.d - b.d)
          .slice(0, 4);

        sorted.forEach(neighbor => {
          ctx.beginPath();
          ctx.moveTo(p1.x, p1.y);
          ctx.lineTo(neighbor.p.x, neighbor.p.y);
          ctx.stroke();
        });
      });
    }

    // Orientation Vectors
    if (toggleOrientation.checked) {
      ctx.strokeStyle = '#FFB300';
      ctx.lineWidth = 1.8;
      const whiskerLen = 14;

      points.forEach(p => {
        const dx = Math.cos(p.theta) * whiskerLen;
        const dy = Math.sin(p.theta) * whiskerLen;
        ctx.beginPath();
        ctx.moveTo(p.x, p.y);
        ctx.lineTo(p.x + dx, p.y + dy);
        ctx.stroke();

        ctx.fillStyle = '#FFB300';
        ctx.beginPath();
        ctx.arc(p.x + dx, p.y + dy, 2, 0, Math.PI * 2);
        ctx.fill();
      });
    }

    // Minutiae Coordinate Points
    if (toggleMinutiae.checked) {
      points.forEach(p => {
        ctx.beginPath();
        ctx.arc(p.x, p.y, 4.5, 0, Math.PI * 2);
        if (p.type === 0) {
          ctx.fillStyle = '#EF4444';
          ctx.shadowColor = '#EF4444';
          ctx.shadowBlur = 8;
        } else {
          ctx.fillStyle = '#10B981';
          ctx.shadowColor = '#10B981';
          ctx.shadowBlur = 8;
        }
        ctx.fill();
        ctx.strokeStyle = '#FFFFFF';
        ctx.lineWidth = 1.2;
        ctx.stroke();
        ctx.shadowBlur = 0;
      });
    }
  }

  // Execute AFIS 3-Tier Query
  btnExecuteQuery.addEventListener('click', async () => {
    if (!activeTemplate) return;

    logConsole(`--------------------------------------------------------------------`, 'prompt');
    logConsole(`[QUERY_INIT] Initiating 3-Tier AFIS Query for Latent: ${activeTemplate.id}`, 'prompt');
    btnExecuteQuery.disabled = true;

    try {
      const res = await fetch('/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(activeTemplate)
      });

      const telemetry = await res.json();
      activeTelemetry = telemetry;

      logConsole(`[TIER_1_BTREE] Category Pre-Filter Pass: Class=${telemetry.query_pattern_class} [${PATTERN_NAMES[telemetry.query_pattern_class] || 'CLASS'}]`, 'tier1');
      logConsole(`  * Traversed ${telemetry.tier1_btree.hops_traversed} B-Tree Node Hops in ${telemetry.tier1_btree.search_time_us.toFixed(2)} \u03BCs`, 'tier1');
      logConsole(`  * Candidate Pool Pruned: ${telemetry.tier1_btree.prune_percentage.toFixed(2)}% (${telemetry.tier1_btree.candidates_pruned} records pruned, ${telemetry.tier1_btree.candidates_retained} retained)`, 'tier1');

      logConsole(`[TIER_2_KDTREE] 2D Spatial Coordinate Matrix Lookups:`, 'tier2');
      logConsole(`  * Traversed ${telemetry.tier2_kdtree.total_spatial_hops} Spatial Hops across partitioned coordinate spaces`, 'tier2');
      logConsole(`  * Branches Pruned via Hyperplane Intersection: ${telemetry.tier2_kdtree.branches_pruned} branches in ${telemetry.tier2_kdtree.execution_time_us.toFixed(2)} \u03BCs`, 'tier2');

      logConsole(`[TIER_3_GRAPH] Dynamic Invariant Minutiae Adjacency Graph Verification:`, 'tier3');
      logConsole(`  * Invariance Matrix Evaluated: ${telemetry.tier3_graph.total_edges_checked} Edges Checked across ${telemetry.tier3_graph.candidates_evaluated} candidates`, 'tier3');
      logConsole(`  * Invariant Edge Congruences Verified: ${telemetry.tier3_graph.total_edges_matched} edges in ${telemetry.tier3_graph.execution_time_us.toFixed(2)} \u03BCs`, 'tier3');

      const topMatch = telemetry.top_candidates[0];
      if (topMatch && topMatch.forensic_score >= 80.0) {
        logConsole(`[FORENSIC_MATCH_CONCORDANCE] IDENTIFICATION CONFIRMED: Exemplar '${topMatch.id}' with Score ${topMatch.forensic_score.toFixed(2)}% (Spatial RMSE: ${topMatch.spatial_rmse.toFixed(2)} px)`, 'match');
      } else {
        logConsole(`[FORENSIC_REPORT] Search completed. Top exemplar: '${topMatch ? topMatch.id : 'NONE'}' (Score: ${topMatch ? topMatch.forensic_score.toFixed(2) : 0}%)`, 'info');
      }

      benchTimerClock.textContent = `${telemetry.benchmarks.total_execution_time_us.toFixed(2)} \u03BCs`;
      mTier1Hops.textContent = `${telemetry.tier1_btree.hops_traversed} HOPS`;
      mTier1Prune.textContent = `PRUNED: ${telemetry.tier1_btree.prune_percentage.toFixed(2)}%`;
      mTier1Time.textContent = `LATENCY: ${telemetry.tier1_btree.search_time_us.toFixed(2)} \u03BCs`;

      mTier2Hops.textContent = `${telemetry.tier2_kdtree.total_spatial_hops} HOPS`;
      mTier2Pruned.textContent = `BRANCHES PRUNED: ${telemetry.tier2_kdtree.branches_pruned}`;
      mTier2Time.textContent = `LATENCY: ${telemetry.tier2_kdtree.execution_time_us.toFixed(2)} \u03BCs`;

      mTier3Edges.textContent = `${telemetry.tier3_graph.total_edges_matched} EDGES`;
      mTier3Eval.textContent = `CHECKED: ${telemetry.tier3_graph.total_edges_checked} EDGES`;
      mTier3Time.textContent = `LATENCY: ${telemetry.tier3_graph.execution_time_us.toFixed(2)} \u03BCs`;

      mTotalTime.textContent = `${telemetry.benchmarks.total_execution_time_us.toFixed(2)} \u03BCs`;
      mRamFootprint.textContent = `RAM: ${(telemetry.benchmarks.total_memory_bytes / 1024.0).toFixed(2)} KB`;
      mPerRecord.textContent = `ALLOC: ${telemetry.benchmarks.memory_per_record_bytes.toFixed(1)} B/REC`;

      renderCandidatesTable(telemetry.top_candidates);

    } catch (err) {
      logConsole(`[ERROR] Search execution error: ${err.message}`, 'warn');
    } finally {
      btnExecuteQuery.disabled = false;
    }
  });

  function renderCandidatesTable(candidates) {
    candidatesTbody.innerHTML = '';
    if (!candidates || candidates.length === 0) {
      candidatesTbody.innerHTML = `<tr><td colspan="10" class="empty-state">No candidates returned from B-Tree filter pass.</td></tr>`;
      return;
    }

    candidates.forEach((c, idx) => {
      const tr = document.createElement('tr');
      if (idx === 0 && c.forensic_score >= 80.0) {
        tr.classList.add('top-match');
      }

      const scoreColor = c.forensic_score >= 80 ? 'text-emerald' : (c.forensic_score >= 20 ? 'text-amber' : 'text-dim');

      tr.innerHTML = `
        <td><strong class="text-cyan">#${c.rank}</strong></td>
        <td><span class="text-white">${c.id}</span></td>
        <td>${PATTERN_NAMES[c.pattern_class] || c.pattern_class}</td>
        <td><strong class="${scoreColor}">${c.forensic_score.toFixed(2)}%</strong></td>
        <td>${c.matched_minutiae} / ${activeTemplate.minutiae.length}</td>
        <td>${c.matched_edges}</td>
        <td>${c.spatial_rmse < 900 ? c.spatial_rmse.toFixed(2) + ' px' : 'N/A'}</td>
        <td>${c.rotation_deg.toFixed(2)}&deg;</td>
        <td>(${c.translation_x.toFixed(1)}, ${c.translation_y.toFixed(1)})</td>
        <td class="text-amber">${c.latency_us.toFixed(1)} &mu;s</td>
      `;

      tr.addEventListener('click', () => {
        openComparisonModal(activeTemplate, c);
      });

      candidatesTbody.appendChild(tr);
    });
  }

  // =========================================================================
  // LIVE ENROLLMENT WORKFLOW
  // =========================================================================
  btnOpenEnroll.addEventListener('click', () => {
    enrollmentModal.classList.remove('hidden');
    stagedEnrollBase64 = null;
    btnCommitEnrollment.disabled = true;
    enrollCaseId.value = `USER_LATENT_${Date.now().toString().slice(-4)}`;
    metaPattern.textContent = 'NOT EXTRACTED';
    metaCount.textContent = '0 POINTS';
    metaBreakdown.textContent = '0 END / 0 BIF';
    metaBytes.textContent = '< 1024 BYTES';
    enrollCtx.clearRect(0, 0, enrollCanvas.width, enrollCanvas.height);
  });

  btnCloseEnroll.addEventListener('click', () => {
    enrollmentModal.classList.add('hidden');
  });

  dropzone.addEventListener('click', () => enrollFileInput.click());

  dropzone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropzone.classList.add('dragover');
  });

  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));

  dropzone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropzone.classList.remove('dragover');
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      handleEnrollFile(e.dataTransfer.files[0]);
    }
  });

  enrollFileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files[0]) {
      handleEnrollFile(e.target.files[0]);
    }
  });

  function handleEnrollFile(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      stagedEnrollBase64 = e.target.result;
      const previewImg = new Image();
      previewImg.onload = () => {
        enrollCtx.clearRect(0, 0, enrollCanvas.width, enrollCanvas.height);
        enrollCtx.drawImage(previewImg, 0, 0, enrollCanvas.width, enrollCanvas.height);
        btnCommitEnrollment.disabled = false;
        metaPattern.textContent = 'PENDING EXTRACTION';
        metaPattern.className = 'text-amber';
      };
      previewImg.src = stagedEnrollBase64;
    };
    reader.readAsDataURL(file);
  }

  btnCommitEnrollment.addEventListener('click', async () => {
    if (!stagedEnrollBase64) return;

    const caseId = enrollCaseId.value.trim() || `USER_LATENT_${Date.now()}`;
    btnCommitEnrollment.disabled = true;
    btnCommitEnrollment.innerHTML = `<span>&#9203;</span> INGESTING INTO C B-TREE &amp; RAM...`;

    try {
      const res = await fetch('/api/enroll', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          id: caseId,
          image_base64: stagedEnrollBase64
        })
      });

      const data = await res.json();
      if (data.status === 'ENROLLED_SUCCESSFULLY') {
        metaPattern.textContent = PATTERN_NAMES[data.pattern_class] || `CLASS ${data.pattern_class}`;
        metaPattern.className = 'text-cyan';
        metaCount.textContent = `${data.minutiae_count} POINTS`;
        metaBreakdown.textContent = `${data.endings_count} END / ${data.bifurcations_count} BIF`;
        metaBytes.textContent = `${data.raw_vector_bytes} BYTES (< 1024 B)`;

        // Fetch newly enrolled template details to draw minutiae overlay
        const tRes = await fetch(`/api/template/${data.id}`);
        const newTemplate = await tRes.json();

        // Draw minutiae on enroll canvas
        drawMinutiaeOverlay(enrollCtx, newTemplate.minutiae);

        logConsole(`====================================================================`, 'prompt');
        logConsole(`[LIVE_ENROLLMENT_SUCCESS] Case '${data.id}' successfully enrolled into C Engine!`, 'match');
        logConsole(`  * Henry Pattern: ${PATTERN_NAMES[data.pattern_class] || data.pattern_class}`, 'tier1');
        logConsole(`  * Extracted Minutiae: ${data.minutiae_count} (${data.endings_count} Endings, ${data.bifurcations_count} Bifurcations)`, 'tier2');
        logConsole(`  * Allocated Memory in Live RAM: ${data.raw_vector_bytes} bytes (< 1024 B budget satisfied)`, 'tier3');
        logConsole(`  * Total Indexed Templates in Database: ${data.total_database_records}`, 'info');

        // Refresh template dropdowns and select new template
        const tListRes = await fetch('/api/templates');
        const tListData = await tListRes.json();
        cachedTemplates = tListData.templates;
        populateTemplateDropdowns();
        selectTemplate.value = data.id;
        loadTemplate(data.id);

        btnCommitEnrollment.innerHTML = `<span>&#10004;</span> ENROLLED IN LIVE RAM INDEX`;
      } else {
        alert('Enrollment error: ' + (data.error || 'Unknown error'));
        btnCommitEnrollment.disabled = false;
        btnCommitEnrollment.innerHTML = `<span>&#10004;</span> COMMIT ENROLLMENT TO LIVE RAM INDEX`;
      }
    } catch (err) {
      alert('Network enrollment error: ' + err.message);
      btnCommitEnrollment.disabled = false;
      btnCommitEnrollment.innerHTML = `<span>&#10004;</span> COMMIT ENROLLMENT TO LIVE RAM INDEX`;
    }
  });

  // =========================================================================
  // ROTATED MATCH VERIFICATION MODE (SPLIT-SCREEN)
  // =========================================================================
  btnOpenRotationMode.addEventListener('click', () => {
    rotationModal.classList.remove('hidden');
    if (activeTemplate) {
      rotSelectTemplate.value = activeTemplate.id;
    }
    executeRotationVerification();
  });

  btnCloseRotation.addEventListener('click', () => {
    rotationModal.classList.add('hidden');
  });

  rotSlider.addEventListener('input', () => {
    rotAngleVal.textContent = `${parseFloat(rotSlider.value) >= 0 ? '+' : ''}${parseFloat(rotSlider.value).toFixed(1)}\u00B0`;
  });

  rotSlider.addEventListener('change', () => {
    presetButtons.forEach(b => b.classList.remove('active'));
    executeRotationVerification();
  });

  presetButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      presetButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      const angle = parseFloat(btn.getAttribute('data-angle'));
      rotSlider.value = angle;
      rotAngleVal.textContent = `${angle >= 0 ? '+' : ''}${angle.toFixed(1)}\u00B0`;
      executeRotationVerification();
    });
  });

  rotSelectTemplate.addEventListener('change', () => {
    executeRotationVerification();
  });

  btnRunRotationTest.addEventListener('click', executeRotationVerification);

  async function executeRotationVerification() {
    const templateId = rotSelectTemplate.value;
    const rotationDeg = parseFloat(rotSlider.value);
    btnRunRotationTest.disabled = true;

    try {
      const res = await fetch('/api/rotate_probe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          template_id: templateId,
          rotation_deg: rotationDeg,
          shift_x: 10.0,
          shift_y: -8.0
        })
      });

      const data = await res.json();
      const topMatch = data.top_candidates[0];

      rotOrigId.textContent = templateId;
      rotQueryId.textContent = `${data.probe_record.id} [${rotationDeg >= 0 ? '+' : ''}${rotationDeg.toFixed(1)}\u00B0]`;

      // Update Live Terminal Line & Metrics
      const isMatch = topMatch && topMatch.id === templateId && topMatch.forensic_score >= 80.0;
      const termMsg = isMatch
        ? `Relative Topology Verification Passed | Rotation Angle Delta Detected: ${topMatch.rotation_deg.toFixed(2)}\u00B0 | Search Latency: ${topMatch.latency_us.toFixed(2)} \u03BCs`
        : `Relative Topology Verification Evaluated | Score: ${topMatch ? topMatch.forensic_score.toFixed(1) : 0}% | Latency: ${topMatch ? topMatch.latency_us.toFixed(1) : 0} \u03BCs`;

      rotTermOutput.textContent = termMsg;
      rotTermOutput.className = isMatch ? 'live-terminal-line text-emerald' : 'live-terminal-line text-amber';

      rotStatTop.textContent = isMatch ? `CONGRUENT MATCH (${topMatch.forensic_score.toFixed(1)}%)` : 'NO CONGRUENCE';
      rotStatTop.className = isMatch ? 'tile-val text-emerald' : 'tile-val text-amber';
      rotStatInj.textContent = `${rotationDeg >= 0 ? '+' : ''}${rotationDeg.toFixed(2)}\u00B0`;
      rotStatDet.textContent = `${topMatch ? topMatch.rotation_deg.toFixed(2) : 0.0}\u00B0`;
      rotStatRmse.textContent = `${topMatch ? topMatch.spatial_rmse.toFixed(2) : 0.0} px`;
      rotStatLat.textContent = `${topMatch ? topMatch.latency_us.toFixed(2) : 0.0} \u03BCs`;

      // Render Split-Screen canvases with matching relative graph edges
      await renderSplitScreenMatch(templateId, data.probe_record, topMatch);

      logConsole(`[ROTATION_INVARIANCE_CHECK] Probe Rotated by ${rotationDeg}\u00B0 vs Exemplar '${templateId}':`, 'prompt');
      logConsole(`  * Injected Rotation: ${rotationDeg}\u00B0 | Detected Rotation: ${topMatch.rotation_deg.toFixed(2)}\u00B0`, 'tier1');
      logConsole(`  * Relative Graph Edge Congruence Score: ${topMatch.forensic_score.toFixed(2)}% (Spatial RMSE: ${topMatch.spatial_rmse.toFixed(2)} px)`, 'tier3');
      logConsole(`  * Search Latency: ${topMatch.latency_us.toFixed(2)} \u03BCs`, 'info');

    } catch (err) {
      rotTermOutput.textContent = `[ERROR] Invariance verification error: ${err.message}`;
      rotTermOutput.className = 'live-terminal-line text-crimson';
    } finally {
      btnRunRotationTest.disabled = false;
    }
  }

  async function renderSplitScreenMatch(origId, probeRecord, matchData) {
    const origCtx = canvasSplitOrig.getContext('2d');
    const rotCtx = canvasSplitRot.getContext('2d');
    const connCtx = canvasSplitConnector.getContext('2d');

    const W = canvasSplitOrig.width;
    const H = canvasSplitOrig.height;

    origCtx.clearRect(0, 0, W, H);
    rotCtx.clearRect(0, 0, W, H);
    connCtx.clearRect(0, 0, canvasSplitConnector.width, canvasSplitConnector.height);

    // Fetch original template
    const tRes = await fetch(`/api/template/${origId}`);
    const origRecord = await tRes.json();

    const scaleX = W / 288.0;
    const scaleY = H / 375.0;

    // Load original image
    const origImg = new Image();
    origImg.onload = () => {
      origCtx.drawImage(origImg, 0, 0, W, H);
      drawGraphAndMinutiae(origCtx, origRecord.minutiae, scaleX, scaleY, '#00E5FF');
      drawMatchedEdges(origCtx, origRecord.minutiae, matchData.matched_edges_list, 2, 3, scaleX, scaleY, '#34D399');
    };
    origImg.src = `/images/${origId}.png`;

    // Load rotated probe image
    const probeImg = new Image();
    probeImg.onload = () => {
      rotCtx.drawImage(probeImg, 0, 0, W, H);
      drawGraphAndMinutiae(rotCtx, probeRecord.minutiae, scaleX, scaleY, '#FFB300');
      drawMatchedEdges(rotCtx, probeRecord.minutiae, matchData.matched_edges_list, 0, 1, scaleX, scaleY, '#34D399');
      drawCorrespondenceLines(connCtx, origRecord.minutiae, probeRecord.minutiae, matchData.matched_points, scaleX, scaleY);
    };
    probeImg.src = `/images/${probeRecord.id}.png`;
  }

  function drawGraphAndMinutiae(ctx, minutiae, scaleX, scaleY, edgeColor) {
    if (!minutiae || minutiae.length === 0) return;

    // Draw K-NN relative graph edges
    ctx.strokeStyle = edgeColor;
    ctx.lineWidth = 1;
    ctx.globalAlpha = 0.3;

    for (let i = 0; i < minutiae.length; ++i) {
      const p1 = minutiae[i];
      for (let j = i + 1; j < minutiae.length; ++j) {
        const p2 = minutiae[j];
        const dx = (p1.x - p2.x);
        const dy = (p1.y - p2.y);
        const d = Math.sqrt(dx * dx + dy * dy);
        if (d < 45.0) {
          ctx.beginPath();
          ctx.moveTo(p1.x * scaleX, p1.y * scaleY);
          ctx.lineTo(p2.x * scaleX, p2.y * scaleY);
          ctx.stroke();
        }
      }
    }
    ctx.globalAlpha = 1.0;

    // Draw minutiae
    minutiae.forEach(m => {
      ctx.beginPath();
      ctx.arc(m.x * scaleX, m.y * scaleY, 4, 0, Math.PI * 2);
      ctx.fillStyle = m.type === 0 ? '#EF4444' : '#10B981';
      ctx.fill();
      ctx.strokeStyle = '#FFFFFF';
      ctx.lineWidth = 1;
      ctx.stroke();
    });
  }

  function drawMatchedEdges(ctx, minutiae, matchedEdgesList, uIdx, vIdx, scaleX, scaleY, color) {
    if (!matchedEdgesList || !minutiae) return;
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    ctx.shadowColor = color;
    ctx.shadowBlur = 6;

    matchedEdgesList.slice(0, 24).forEach(edge => {
      const u = edge[uIdx];
      const v = edge[vIdx];
      if (u < minutiae.length && v < minutiae.length) {
        ctx.beginPath();
        ctx.moveTo(minutiae[u].x * scaleX, minutiae[u].y * scaleY);
        ctx.lineTo(minutiae[v].x * scaleX, minutiae[v].y * scaleY);
        ctx.stroke();
      }
    });
    ctx.shadowBlur = 0;
  }

  function drawCorrespondenceLines(ctx, origPts, probePts, matchedPts, scaleX, scaleY) {
    if (!matchedPts || !origPts || !probePts) return;
    const connW = canvasSplitConnector.width;

    ctx.lineWidth = 1.2;
    ctx.setLineDash([3, 3]);

    matchedPts.slice(0, 16).forEach((pair, idx) => {
      const qIdx = pair[0];
      const cIdx = pair[1];

      if (qIdx < probePts.length && cIdx < origPts.length) {
        const y1 = origPts[cIdx].y * scaleY;
        const y2 = probePts[qIdx].y * scaleY;

        ctx.strokeStyle = `hsl(${(idx * 28) % 360}, 100%, 65%)`;
        ctx.beginPath();
        ctx.moveTo(0, y1);
        ctx.bezierCurveTo(connW * 0.4, y1, connW * 0.6, y2, connW, y2);
        ctx.stroke();
      }
    });
    ctx.setLineDash([]);
  }

  // =========================================================================
  // STANDARD DUAL COMPARISON MODAL
  // =========================================================================
  async function openComparisonModal(queryRecord, candidate) {
    cmpQueryId.textContent = queryRecord.id;
    cmpMatchId.textContent = `${candidate.id} [${candidate.forensic_score.toFixed(2)}% Concordance]`;

    comparisonModal.classList.remove('hidden');

    const qCtx = cmpQueryCanvas.getContext('2d');
    const mCtx = cmpMatchCanvas.getContext('2d');

    try {
      const res = await fetch(`/api/template/${candidate.id}`);
      const candRecord = await res.json();

      const qImg = new Image();
      qImg.onload = () => {
        qCtx.drawImage(qImg, 0, 0, 288, 375);
        drawMinutiaeOverlay(qCtx, queryRecord.minutiae);
      };
      qImg.src = `/images/${queryRecord.id}.png`;

      const mImg = new Image();
      mImg.onload = () => {
        mCtx.drawImage(mImg, 0, 0, 288, 375);
        drawMinutiaeOverlay(mCtx, candRecord.minutiae);
      };
      mImg.src = `/images/${candidate.id}.png`;

      cmpDiagnostics.innerHTML = `
        <div><strong class="text-muted">RIGID ROTATION:</strong> <span class="text-amber">${candidate.rotation_deg.toFixed(2)}&deg;</span></div>
        <div><strong class="text-muted">RIGID TRANSLATION:</strong> <span class="text-cyan">(\u0394X: ${candidate.translation_x.toFixed(1)}, \u0394Y: ${candidate.translation_y.toFixed(1)})</span></div>
        <div><strong class="text-muted">SPATIAL RMSE:</strong> <span class="text-emerald">${candidate.spatial_rmse.toFixed(2)} px</span></div>
      `;
    } catch (e) {
      console.error(e);
    }
  }

  function drawMinutiaeOverlay(context, minutiae) {
    if (!minutiae) return;
    minutiae.forEach(m => {
      context.beginPath();
      context.arc(m.x, m.y, 3.5, 0, Math.PI * 2);
      context.fillStyle = m.type === 0 ? '#EF4444' : '#10B981';
      context.fill();
      context.strokeStyle = '#FFFFFF';
      context.lineWidth = 1;
      context.stroke();
    });
  }

  btnCloseModal.addEventListener('click', () => {
    comparisonModal.classList.add('hidden');
  });

  // Benchmark Suite Execution
  btnRunBenchmark.addEventListener('click', async () => {
    logConsole(`====================================================================`, 'prompt');
    logConsole(`[BENCHMARK_START] Triggering C POSIX / QPC Benchmark on All Templates...`, 'prompt');
    btnRunBenchmark.disabled = true;

    try {
      const res = await fetch('/api/benchmark');
      const data = await res.json();
      if (data.raw_output) {
        const lines = data.raw_output.split('\n');
        lines.forEach(l => {
          if (l.trim()) logConsole(l, 'info');
        });
      }
    } catch (err) {
      logConsole(`[ERROR] Benchmark error: ${err.message}`, 'warn');
    } finally {
      btnRunBenchmark.disabled = false;
    }
  });

  btnClearConsole.addEventListener('click', () => {
    consoleTerminal.innerHTML = '<div class="term-line prompt">AFIS:~$ Console cleared. System ready.</div>';
  });

  function logConsole(message, type = 'info') {
    const line = document.createElement('div');
    line.className = `term-line ${type}`;
    line.textContent = message;
    consoleTerminal.appendChild(line);
    consoleTerminal.scrollTop = consoleTerminal.scrollHeight;
  }
});
