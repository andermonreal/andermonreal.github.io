/*
 * Command palette / keyboard navigation (loaded on every page from
 * _includes/sidebar.html).
 *
 *   Ctrl/⌘ K  or  /   → open the palette (jump to any page or writeup)
 *   g then h/m/c/p/s/r → go straight to Home / Machines / CVEs / Projects /
 *                        Arsenal (skills) / Archives
 *   ↑ ↓ Enter Esc      → move, open, close
 *
 * Pages come from the current language (<html lang>); writeups are loaded once
 * from the same /assets/js/data/search.json the topbar search uses, and their
 * URLs are localised. The overlay is built lazily on first open and follows the
 * combobox/listbox ARIA pattern. Styles: the "Command palette" SCSS section.
 */
(function () {
  'use strict';

  const ES = document.documentElement.lang.toLowerCase().startsWith('es');
  const t = (en, es) => (ES ? es : en);
  const prefix = ES ? '/es' : '';
  const rel = (p) => `${prefix}${p}`;

  const PAGES = [
    { title: t('Home', 'Inicio'), url: rel('/'), icon: 'fa-house', key: 'h' },
    { title: t('Machines', 'Máquinas'), url: rel('/machines/'), icon: 'fa-server', key: 'm' },
    { title: 'CVEs', url: rel('/cves/'), icon: 'fa-bug', key: 'c' },
    { title: t('Projects', 'Proyectos'), url: rel('/projects/'), icon: 'fa-diagram-project', key: 'p' },
    { title: t('Arsenal', 'Arsenal'), url: rel('/arsenal/'), icon: 'fa-toolbox', key: 's' },
    { title: t('Archives', 'Archivo'), url: rel('/archives/'), icon: 'fa-box-archive', key: 'r' }
  ];

  const GOTO = {};
  PAGES.forEach((p) => {
    GOTO[p.key] = p.url;
  });

  let overlay, input, list, statusEl;
  let items = []; // current results: [{title, url, icon, badge, sub}]
  let active = -1;
  let writeups = null; // lazily fetched
  let built = false;
  let awaitingG = false;
  let gTimer = null;

  const isTyping = () => {
    const el = document.activeElement;
    return el && (el.tagName === 'INPUT' || el.tagName === 'TEXTAREA' || el.isContentEditable);
  };

  function loadWriteups() {
    if (writeups || !window.fetch) {
      return Promise.resolve(writeups || []);
    }

    // Assets are not localised — always the site-root path.
    return fetch('/assets/js/data/search.json')
      .then((r) => r.json())
      .then((data) => {
        writeups = data.map((w) => ({
          title: w.title,
          url: `${prefix}${w.url}`,
          icon: 'fa-flag',
          badge: w.diff || '',
          badgeslug: w.diffslug || '',
          locked: !!w.locked,
          sub: [w.platform, w.os].filter(Boolean).join(' · '),
          hay: `${w.title} ${w.tags} ${w.platform} ${w.os}`.toLowerCase()
        }));
        return writeups;
      })
      .catch(() => {
        writeups = [];
        return writeups;
      });
  }

  function build() {
    if (built) {
      return;
    }

    built = true;

    overlay = document.createElement('div');
    overlay.className = 'cmdk';
    overlay.hidden = true;
    overlay.innerHTML = `
      <div class="cmdk-panel" role="dialog" aria-modal="true" aria-label="${t('Command palette', 'Paleta de comandos')}">
        <div class="cmdk-inputwrap">
          <i class="fas fa-magnifying-glass" aria-hidden="true"></i>
          <input class="cmdk-input" type="text" role="combobox" aria-expanded="true"
                 aria-controls="cmdk-list" aria-autocomplete="list" autocomplete="off"
                 spellcheck="false" placeholder="${t('Jump to a page or writeup…', 'Ir a una página o writeup…')}"
                 aria-label="${t('Search pages and writeups', 'Buscar páginas y writeups')}">
          <kbd class="cmdk-esc">Esc</kbd>
        </div>
        <ul class="cmdk-list" id="cmdk-list" role="listbox" aria-label="${t('Results', 'Resultados')}"></ul>
        <div class="cmdk-foot" aria-hidden="true">
          <span><kbd>↑</kbd><kbd>↓</kbd> ${t('move', 'moverse')}</span>
          <span><kbd>↵</kbd> ${t('open', 'abrir')}</span>
          <span><kbd>g</kbd> ${t('then', 'luego')} <kbd>h</kbd><kbd>m</kbd><kbd>c</kbd><kbd>p</kbd><kbd>s</kbd><kbd>r</kbd></span>
        </div>
      </div>
      <p class="visually-hidden" id="cmdk-status" role="status" aria-live="polite"></p>`;

    document.body.appendChild(overlay);
    input = overlay.querySelector('.cmdk-input');
    list = overlay.querySelector('.cmdk-list');
    statusEl = overlay.querySelector('#cmdk-status');

    overlay.addEventListener('mousedown', (e) => {
      if (e.target === overlay) {
        close();
      }
    });
    input.addEventListener('input', () => render(input.value));
    input.addEventListener('keydown', onKey);
  }

  function score(hay, q) {
    const i = hay.indexOf(q);
    if (i === -1) {
      return -1;
    }
    return (i === 0 ? 1000 : 0) - i; // prefer prefix matches
  }

  function render(query) {
    const q = query.trim().toLowerCase();
    const pageHits = PAGES.map((p) => ({ ...p })).filter((p) => !q || p.title.toLowerCase().includes(q));

    let wuHits = [];
    if (writeups) {
      wuHits = writeups
        .map((w) => ({ w, s: q ? score(w.hay, q) : 0 }))
        .filter((x) => x.s >= 0)
        .sort((a, b) => b.s - a.s)
        .slice(0, q ? 8 : 5)
        .map((x) => x.w);
    }

    items = pageHits.concat(wuHits);
    list.replaceChildren();

    items.forEach((it, idx) => {
      const li = document.createElement('li');
      li.className = 'cmdk-item';
      li.id = `cmdk-opt-${idx}`;
      li.setAttribute('role', 'option');
      li.setAttribute('aria-selected', 'false');

      const icon = document.createElement('i');
      icon.className = `fas ${it.icon} cmdk-ico`;
      icon.setAttribute('aria-hidden', 'true');
      li.appendChild(icon);

      const body = document.createElement('span');
      body.className = 'cmdk-body';
      const name = document.createElement('span');
      name.className = 'cmdk-name';
      name.textContent = it.title;
      body.appendChild(name);
      if (it.sub) {
        const sub = document.createElement('span');
        sub.className = 'cmdk-sub';
        sub.textContent = it.sub;
        body.appendChild(sub);
      }
      li.appendChild(body);

      if (it.locked) {
        const lock = document.createElement('i');
        lock.className = 'fas fa-lock cmdk-lock';
        lock.setAttribute('aria-hidden', 'true');
        li.appendChild(lock);
      }
      if (it.badge) {
        const b = document.createElement('span');
        b.className = `difficulty-badge difficulty-${it.badgeslug}`;
        b.textContent = it.badge;
        li.appendChild(b);
      }

      li.addEventListener('mousemove', () => setActive(idx));
      li.addEventListener('click', () => go(idx));
      list.appendChild(li);
    });

    setActive(items.length ? 0 : -1);
    statusEl.textContent = `${items.length} ${t('results', 'resultados')}`;
  }

  function setActive(idx) {
    active = idx;
    Array.from(list.children).forEach((li, i) => {
      const on = i === idx;
      li.classList.toggle('is-active', on);
      li.setAttribute('aria-selected', on ? 'true' : 'false');
      if (on) {
        input.setAttribute('aria-activedescendant', li.id);
        li.scrollIntoView({ block: 'nearest' });
      }
    });
    if (idx === -1) {
      input.removeAttribute('aria-activedescendant');
    }
  }

  function go(idx) {
    const it = items[idx];
    if (it) {
      window.location.assign(it.url);
    }
  }

  function onKey(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setActive(items.length ? (active + 1) % items.length : -1);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setActive(items.length ? (active - 1 + items.length) % items.length : -1);
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (active >= 0) {
        go(active);
      }
    } else if (e.key === 'Escape') {
      e.preventDefault();
      close();
    }
  }

  let lastFocus = null;

  function open() {
    build();
    lastFocus = document.activeElement;
    overlay.hidden = false;
    document.body.classList.add('cmdk-open');
    input.value = '';
    render('');
    input.focus();
    loadWriteups().then(() => {
      if (!overlay.hidden) {
        render(input.value);
      }
    });
  }

  function close() {
    if (!overlay || overlay.hidden) {
      return;
    }
    overlay.hidden = true;
    document.body.classList.remove('cmdk-open');
    if (lastFocus && lastFocus.focus) {
      lastFocus.focus();
    }
  }

  document.addEventListener('keydown', (e) => {
    // Open: Ctrl/Cmd+K anywhere; "/" only when not already typing.
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
      e.preventDefault();
      open();
      return;
    }

    if (overlay && !overlay.hidden) {
      return; // the input's own handler deals with keys while open
    }

    if (e.key === '/' && !isTyping()) {
      e.preventDefault();
      open();
      return;
    }

    // "g" then a letter → go to a section.
    if (awaitingG && !isTyping()) {
      const dest = GOTO[e.key.toLowerCase()];
      awaitingG = false;
      window.clearTimeout(gTimer);
      if (dest) {
        e.preventDefault();
        window.location.assign(dest);
      }
      return;
    }

    if (e.key.toLowerCase() === 'g' && !isTyping() && !e.ctrlKey && !e.metaKey && !e.altKey) {
      awaitingG = true;
      gTimer = window.setTimeout(() => {
        awaitingG = false;
      }, 1200);
    }
  });
})();
