/**
 * Automated test suite for MerkleChain Dashboard Navigation & Routing
 * Validates the 3-level application architecture:
 * Level 1: Landing Page (#home)
 * Level 2: Local Workspace (#local-overview, #synchronize, #versions, #algorithm, #activity, etc.)
 * Level 3: Peer Network Workspace (#overview, #pairing, #connection, #peer-sync, #approval, etc.)
 */
const fs = require('fs');
const path = require('path');
const assert = require('assert');

const projectRoot = path.resolve(__dirname, '..');
const htmlContent = fs.readFileSync(path.join(projectRoot, 'web', 'index.html'), 'utf8');
const jsContent = fs.readFileSync(path.join(projectRoot, 'web', 'app.js'), 'utf8');

console.log('=== Running Frontend Navigation Test Suite ===');

// 1. Verify HTML Structure
const expectedViews = [
  'home', 'network-select',
  'host-overview', 'host-clients', 'host-submissions', 'host-workspace', 'host-review', 'host-publish', 'host-versions', 'host-activity',
  'client-overview', 'client-submit', 'client-submissions', 'client-review', 'client-receive', 'client-versions', 'client-account',
  'local-overview',
  'overview', 'pairing', 'connection', 'peer-sync', 'approval', 'progress', 'peer-activity',
  'synchronize', 'versions', 'algorithm', 'merkle', 'chunks', 'scheduler',
  'activity', 'settings'
];

expectedViews.forEach(v => {
  assert(htmlContent.includes(`id="view-${v}"`), `View section #view-${v} missing in HTML`);
});

// Sidebar links exist for workspace views
const sidebarViews = [
  'local-overview',
  'synchronize', 'versions', 'algorithm', 'activity',
  'overview', 'pairing', 'connection', 'peer-sync', 'approval', 'progress', 'peer-activity',
  'settings'
];
sidebarViews.forEach(v => {
  assert(htmlContent.includes(`data-view="${v}"`), `Nav link for view "${v}" missing in HTML`);
});

assert(!htmlContent.includes('data-view="devices"'), 'Devices & Access sidebar link must be removed from HTML');
assert(!htmlContent.includes('data-view="benchmarks"'), 'Benchmarks sidebar link must be removed from HTML');
assert(!htmlContent.includes('id="view-benchmarks"'), 'Benchmarks view section must be removed from HTML');
console.log(`[PASS] All ${expectedViews.length} views and navigation items present in HTML.`);

// 2. Verify validViews Set in app.js
const validViewsMatch = jsContent.match(/const\s+validViews\s*=\s*new\s+Set\(\[\s*([\s\S]*?)\]\);/);
assert(validViewsMatch, 'validViews set not found in app.js');
const validViewsInJs = validViewsMatch[1]
  .replace(/\/\/[^\n]*/g, '')
  .split(',')
  .map(s => s.replace(/["'\s]/g, ''))
  .filter(Boolean);

expectedViews.forEach(v => {
  assert(validViewsInJs.includes(v), `View "${v}" missing from validViews Set in app.js`);
});
assert.strictEqual(validViewsInJs.length, expectedViews.length, 'validViews length mismatch');
console.log(`[PASS] app.js validViews contains exactly all ${expectedViews.length} view routes.`);

// 3. Mock DOM & Event Simulation Environment
class MockClassList {
  constructor() { this.classes = new Set(); }
  add(c) { this.classes.add(c); }
  remove(c) { this.classes.delete(c); }
  toggle(c, force) {
    if (force === undefined) {
      if (this.classes.has(c)) { this.classes.delete(c); return false; }
      else { this.classes.add(c); return true; }
    }
    if (force) this.classes.add(c);
    else this.classes.delete(c);
    return force;
  }
  contains(c) { return this.classes.has(c); }
  get value() { return Array.from(this.classes).join(' '); }
}

class MockElement {
  constructor(id, tagName = 'div', dataset = {}, classes = '') {
    this.id = id;
    this.tagName = tagName;
    this.dataset = dataset;
    this.classList = new MockClassList();
    if (classes) classes.split(/\s+/).forEach(c => this.classList.add(c));
    this.textContent = '';
    this.children = [];
    this.listeners = {};
    this.value = '';
    this.disabled = false;
  }
  addEventListener(event, fn) {
    if (!this.listeners[event]) this.listeners[event] = [];
    this.listeners[event].push(fn);
  }
  dispatchEvent(event) {
    const list = this.listeners[event.type] || [];
    list.forEach(fn => fn(event));
  }
  replaceChildren(...kids) { this.children = kids; }
  append(...kids) { this.children.push(...kids); }
}

class MockDocument {
  constructor() {
    this.elements = new Map();
    this.elementsByClass = new Map();
    this.views = [];
    this.dataViews = [];
    this.dataGos = [];
    this.body = new MockElement('body');
  }
  register(el) {
    if (el.id) this.elements.set(el.id, el);
    if (el.classList.contains('view')) this.views.push(el);
    if (el.dataset.view) this.dataViews.push(el);
    if (el.dataset.go) this.dataGos.push(el);
  }
  getElementById(id) {
    if (id === 'body') return this.body;
    return this.elements.get(id) || null;
  }
  querySelector(sel) {
    if (sel === 'body') return this.body;
    if (sel.startsWith('#')) return this.elements.get(sel.slice(1)) || null;
    return null;
  }
  querySelectorAll(sel) {
    if (sel === '.view') return this.views;
    if (sel === '[data-view]') return this.dataViews;
    if (sel === '[data-go]') return this.dataGos;
    return [];
  }
}

// Build environment from HTML
function createEnvironment(initialHash = '') {
  const doc = new MockDocument();
  let currentHash = initialHash;
  const historyStack = [currentHash];
  let historyIdx = 0;
  const windowListeners = {};

  const win = {
    addEventListener: (type, fn) => {
      if (!windowListeners[type]) windowListeners[type] = [];
      windowListeners[type].push(fn);
    },
    location: {
      get hash() { return currentHash; },
      set hash(val) {
        if (currentHash !== val) {
          currentHash = val;
          historyStack.splice(historyIdx + 1);
          historyStack.push(val);
          historyIdx = historyStack.length - 1;
          const fns = windowListeners['hashchange'] || [];
          fns.forEach(fn => fn({ type: 'hashchange' }));
        }
      },
      port: '47831'
    },
    history: {
      replaceState: (state, title, url) => {
        currentHash = url;
        historyStack[historyIdx] = url;
      },
      back: () => {
        if (historyIdx > 0) {
          historyIdx--;
          currentHash = historyStack[historyIdx];
          const fns = windowListeners['hashchange'] || [];
          fns.forEach(fn => fn({ type: 'hashchange' }));
        }
      },
      forward: () => {
        if (historyIdx < historyStack.length - 1) {
          historyIdx++;
          currentHash = historyStack[historyIdx];
          const fns = windowListeners['hashchange'] || [];
          fns.forEach(fn => fn({ type: 'hashchange' }));
        }
      }
    }
  };

  // Register breadcrumbs & connection indicators
  doc.register(new MockElement('breadcrumb-section'));
  doc.register(new MockElement('breadcrumb-current'));
  doc.register(new MockElement('server-port'));
  doc.register(new MockElement('clock'));
  doc.register(new MockElement('connection-status'));
  doc.register(new MockElement('workspace-status-pill'));
  doc.register(new MockElement('workspace-sidebar-indicator'));
  doc.register(new MockElement('workspace-brand-link'));
  doc.register(new MockElement('workspace-switch-btn'));
  doc.register(new MockElement('app-sidebar'));
  doc.register(new MockElement('local-recent-sync-tbody'));

  // Register views
  expectedViews.forEach(v => {
    doc.register(new MockElement(`view-${v}`, 'div', {}, 'view'));
  });

  // Register nav links
  expectedViews.forEach(v => {
    doc.register(new MockElement(`nav-${v}`, 'a', { view: v }, 'nav-item'));
  });

  // Action buttons
  const buttons = [
    { id: 'btn-open-local-ws', target: 'local-overview' },
    { id: 'btn-open-network-ws', target: 'overview' },
    { id: 'btn-go-pairing', target: 'pairing' },
    { id: 'btn-go-connection', target: 'connection' },
    { id: 'btn-go-progress', target: 'progress' },
    { id: 'btn-go-peer-sync', target: 'peer-sync' },
    { id: 'btn-go-peer-activity', target: 'peer-activity' },
    { id: 'btn-go-approval', target: 'approval' },
    { id: 'btn-go-synchronize', target: 'synchronize' },
    { id: 'btn-go-versions', target: 'versions' },
    { id: 'btn-go-algorithm', target: 'algorithm' },
    { id: 'btn-go-activity', target: 'activity' }
  ];

  buttons.forEach(({ id, target }) => {
    doc.register(new MockElement(id, 'button', { go: target }));
  });

  return { doc, win };
}

// Helper to run app.js in a mocked context
function runTestInContext(initialHash = '') {
  const { doc, win } = createEnvironment(initialHash);
  const vm = require('vm');

  const context = {
    window: win,
    location: win.location,
    history: win.history,
    document: doc,
    navigator: { onLine: true },
    fetch: () => Promise.resolve({
      ok: true,
      json: () => Promise.resolve({ status: 'ok', logs: [], sessions: [], snapshots: [] }),
      text: () => Promise.resolve('')
    }),
    setInterval: () => 1,
    clearInterval: () => {},
    setTimeout: (fn) => { fn(); return 1; },
    clearTimeout: () => {},
    console: { log: () => {}, warn: () => {}, error: () => {} }
  };

  vm.createContext(context);
  vm.runInContext(jsContent, context);

  // Trigger DOMContentLoaded
  const dcl = context.document.listeners ? context.document.listeners['DOMContentLoaded'] : null;
  // Or check window listener
  return { doc, win, context };
}

// Test A: Default load opens Landing Page with normalized #home hash
{
  const { doc, win } = runTestInContext('');
  assert.strictEqual(doc.getElementById('view-home').classList.contains('active'), true, 'Home (Landing Page) view should be active on initial load');
  assert.strictEqual(doc.getElementById('view-overview').classList.contains('active'), false, 'Peer overview view should NOT be active on default load');
  assert.strictEqual(win.location.hash, '#home', 'Hash should be #home on empty initial route');
  console.log('[PASS] Test A: Default load opens Landing Page with normalized #home hash.');
}

// Test B: Direct load with deep hash #algorithm
{
  const { doc, win } = runTestInContext('#algorithm');
  assert.strictEqual(doc.getElementById('view-algorithm').classList.contains('active'), true, 'Algorithm view should be active');
  assert.strictEqual(doc.getElementById('view-overview').classList.contains('active'), false, 'Overview view should NOT be active');
  assert.strictEqual(doc.getElementById('nav-algorithm').classList.contains('active'), true, 'Algorithm nav should be active');
  assert.strictEqual(win.location.hash, '#algorithm', 'Hash should remain #algorithm');
  console.log('[PASS] Test B: Direct URL open with #algorithm activates Algorithm Explorer view.');
}

// Test C: Direct load with unknown/invalid hash falls back safely to Home
{
  const { doc, win } = runTestInContext('#nonexistent-page');
  assert.strictEqual(doc.getElementById('view-home').classList.contains('active'), true, 'Home view should be active on invalid hash');
  assert.strictEqual(win.location.hash, '#home', 'Hash should fallback and normalize to #home');
  console.log('[PASS] Test C: Invalid URL hash falls back safely to Home.');
}

// Test D: Landing Page cards navigate to Local Workspace and Network Workspace
{
  const { doc, win } = runTestInContext('#home');
  const btnLocal = doc.getElementById('btn-open-local-ws');
  assert(btnLocal, 'btn-open-local-ws missing');
  btnLocal.dispatchEvent({ type: 'click', preventDefault: () => {} });
  assert.strictEqual(win.location.hash, '#local-overview', 'Clicking Open Local Workspace should navigate to #local-overview');
  assert.strictEqual(doc.getElementById('view-local-overview').classList.contains('active'), true, 'Local Overview must be active');

  // Go back to home
  win.location.hash = '#home';
  assert.strictEqual(doc.getElementById('view-home').classList.contains('active'), true);

  const btnNetwork = doc.getElementById('btn-open-network-ws');
  assert(btnNetwork, 'btn-open-network-ws missing');
  btnNetwork.dispatchEvent({ type: 'click', preventDefault: () => {} });
  assert.strictEqual(win.location.hash, '#overview', 'Clicking Open Network Workspace should navigate to #overview');
  assert.strictEqual(doc.getElementById('view-overview').classList.contains('active'), true, 'Peer Overview must be active');
  console.log('[PASS] Test D: Landing page cards navigate correctly to Local and Network workspaces.');
}

// Test E: Sidebar navigation in Local and Network workspaces
{
  const { doc, win } = runTestInContext('#local-overview');
  sidebarViews.forEach(target => {
    const navLink = doc.getElementById(`nav-${target}`);
    assert(navLink, `Nav link for ${target} not found`);
    navLink.dispatchEvent({ type: 'click', preventDefault: () => {}, button: 0 });

    assert.strictEqual(win.location.hash, `#${target}`, `URL hash did not update to #${target}`);
    assert.strictEqual(doc.getElementById(`view-${target}`).classList.contains('active'), true, `View #view-${target} not active`);
    assert.strictEqual(navLink.classList.contains('active'), true, `Nav link for ${target} not marked active`);
  });
  console.log(`[PASS] Test E: Successfully navigated through all ${sidebarViews.length} sidebar views.`);
}

// Test F: Browser Back and Forward navigation history
{
  const { doc, win } = runTestInContext('#home');
  
  // Navigate: home -> local-overview -> algorithm -> versions -> overview
  win.location.hash = '#local-overview';
  win.location.hash = '#algorithm';
  win.location.hash = '#versions';
  win.location.hash = '#overview';

  // Back to versions
  win.history.back();
  assert.strictEqual(win.location.hash, '#versions', 'Hash should be #versions after 1st back');
  assert.strictEqual(doc.getElementById('view-versions').classList.contains('active'), true);

  // Back to algorithm
  win.history.back();
  assert.strictEqual(win.location.hash, '#algorithm', 'Hash should be #algorithm after 2nd back');
  assert.strictEqual(doc.getElementById('view-algorithm').classList.contains('active'), true);

  // Back to local-overview
  win.history.back();
  assert.strictEqual(win.location.hash, '#local-overview', 'Hash should be #local-overview after 3rd back');
  assert.strictEqual(doc.getElementById('view-local-overview').classList.contains('active'), true);

  // Back to home
  win.history.back();
  assert.strictEqual(win.location.hash, '#home', 'Hash should be #home after 4th back');
  assert.strictEqual(doc.getElementById('view-home').classList.contains('active'), true);

  // Forward to local-overview
  win.history.forward();
  assert.strictEqual(win.location.hash, '#local-overview');
  assert.strictEqual(doc.getElementById('view-local-overview').classList.contains('active'), true);

  console.log('[PASS] Test F: Browser Back and Forward history navigation correctly transitions views across levels.');
}

// Test G: Deprecated routes redirect safely
{
  const { doc, win } = runTestInContext('#devices');
  assert.strictEqual(doc.getElementById('view-synchronize').classList.contains('active'), true);
  assert.strictEqual(win.location.hash, '#synchronize');

  const env2 = runTestInContext('#benchmarks');
  assert.strictEqual(env2.doc.getElementById('view-overview').classList.contains('active'), true);
  assert.strictEqual(env2.win.location.hash, '#overview');
  console.log('[PASS] Test G: Deprecated routes redirect safely.');
}

console.log('=== All Frontend Navigation Tests Passed Successfully ===');
