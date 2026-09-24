/*
 * The home page terminal (_layouts/home.html).
 *
 * It types a short intro, then takes commands: help, whoami, about, neofetch,
 * ls, cat, open, cd, stats, certs, contact, clear… with Tab completion and
 * ↑/↓ history. Everything it knows comes from the page's
 * <template id="term-data">, rendered by Liquid in the page's language (and
 * whose links polyglot rewrites for /es/). Output is built from DOM nodes
 * only: nothing a visitor types is ever parsed as HTML.
 *
 * Hidden in it is a small privilege-escalation puzzle: a root-only `.flag`
 * and a sudo rule that allows /usr/bin/base64 (the GTFOBins file read).
 * Solving it prints a note with the contact details; `hint` nudges along.
 *
 * Copy is bilingual, picked from <html lang>. Styles: "The terminal" section
 * of assets/css/jekyll-theme-chirpy.scss.
 */
(function () {
  'use strict';

  const term = document.querySelector('.terminal[data-term]');

  if (!term) {
    return;
  }

  term.setAttribute('data-booted', '');

  const ES = document.documentElement.lang.toLowerCase().startsWith('es');
  const t = (en, es) => (ES ? es : en);
  const REDUCED = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const body = term.querySelector('.terminal-body');
  const intro = term.querySelector('.t-intro');
  const log = term.querySelector('.t-log');
  const form = term.querySelector('.t-prompt');
  const input = term.querySelector('.t-input');
  const chips = Array.from(term.querySelectorAll('.t-suggest button'));

  /* ---- What the terminal knows ------------------------------------------ */

  const tpl = document.getElementById('term-data');
  const items = tpl ? Array.from(tpl.content.querySelectorAll('[data-kind]')) : [];
  const ofKind = (kind) => items.filter((n) => n.dataset.kind === kind);

  const pages = {};
  ofKind('page').forEach((n) => {
    pages[n.dataset.name] = n.getAttribute('href');
  });

  const machines = ofKind('machine')
    .map((n) => ({
      slug: n.dataset.slug,
      title: n.dataset.title,
      diff: n.dataset.diff || '',
      os: n.dataset.os || '',
      platform: n.dataset.platform || '',
      date: n.dataset.date || '',
      locked: n.hasAttribute('data-locked'),
      cves: (n.dataset.cves || '').split(' ').filter(Boolean),
      summary: n.dataset.summary || '',
      href: n.getAttribute('href')
    }))
    .sort((a, b) => (a.date < b.date ? 1 : a.date > b.date ? -1 : 0));

  const projects = ofKind('project').map((n) => ({
    slug: n.dataset.slug,
    title: n.dataset.title,
    href: n.getAttribute('href')
  }));

  const certs = ofKind('cert').map((n) => ({
    name: n.dataset.name,
    full: n.dataset.full,
    issuer: n.dataset.issuer,
    done: n.dataset.status === 'done',
    when: n.dataset.when
  }));

  const contacts = ofKind('contact').map((n) => ({
    name: n.dataset.name,
    href: n.getAttribute('href'),
    text: n.textContent.trim()
  }));

  const logoNode = ofKind('logo')[0];
  const logo = logoNode ? logoNode.textContent.replace(/^\n+|\s+$/g, '') : '';

  const LEVELS = ['Easy', 'Medium', 'Hard', 'Insane'];
  const SYSTEMS = ['linux', 'windows', 'android'];
  const FILES = ['about.txt', 'certs.txt', 'contact.txt'];
  const DIRS = ['machines', 'cves', 'projects', 'archive'];

  /* The flag, stored the way `sudo base64 .flag` prints it. */
  const FLAG_B64 = 'ZmxhZ3toMXIzX20zXzFfcjAwdF90aDFuZ3N9';
  const FLAG = window.atob(FLAG_B64);

  const state = {
    history: [],
    cursor: 0,
    tabs: 0,
    sawFlag: false,
    denied: false,
    sudoList: false,
    gotB64: false,
    solved: false
  };

  const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);
  const machineNames = () => machines.map((m) => m.slug);

  const cveList = () => {
    const seen = new Set();
    machines.forEach((m) => m.cves.forEach((c) => seen.add(c)));
    const key = (c) => {
      const [, year, num] = c.split('-');
      return Number(year) * 1e7 + Number(num);
    };
    return Array.from(seen).sort((a, b) => key(b) - key(a));
  };

  const findMachine = (name) => {
    const n = name.toLowerCase().replace(/\/+$/, '');
    return machines.find((m) => m.slug === n || m.title.toLowerCase() === n);
  };

  /* A summary cut at a length limit ("… opens a pa...") ends on its last
     full sentence instead. */
  const wholeSentences = (text) => {
    if (!/(\.\.\.|…)$/.test(text)) {
      return text;
    }

    const end = Math.max(text.lastIndexOf('. '), text.lastIndexOf('! '), text.lastIndexOf('? '));
    return end > 60 ? text.slice(0, end + 1) : text;
  };

  const isFlagPath = (p) => ['.flag', './.flag', '~/.flag', '/home/ander/.flag'].includes(p);

  /* ---- Output ------------------------------------------------------------- */

  const node = (tag, cls, ...kids) => {
    const el = document.createElement(tag);

    if (cls) {
      el.className = cls;
    }

    kids.flat(Infinity).forEach((k) => {
      if (k !== null && k !== undefined && k !== false) {
        el.append(k instanceof Node ? k : String(k));
      }
    });

    return el;
  };

  const span = (cls, text) => node('span', cls, text);

  const link = (href, text) => {
    const a = node('a', null, text);
    a.href = href;

    if (/^https?:/.test(href)) {
      a.target = '_blank';
      a.rel = 'noopener';
    }

    return a;
  };

  const emit = (el) => {
    log.append(el);
    return el;
  };

  const line = (cls, ...kids) => emit(node('div', `t-line t-out${cls ? ` ${cls}` : ''}`, ...kids));
  const blank = () => line(null, '\u00a0');
  const note = (text) => line('t-dim', `# ${text}`);
  const grid = (cls, cells) => emit(node('div', `t-grid ${cls}`, cells));

  const lockIcon = (label = true) => {
    const icon = node('i', 'fas fa-lock t-lock');
    icon.setAttribute('aria-hidden', 'true');
    return label ? [icon, span('visually-hidden', t(' (protected)', ' (protegido)'))] : [icon];
  };

  const diffClass = (m) => (m.diff ? `t-${m.diff.toLowerCase()}` : 't-hi');

  const machineName = (m) => {
    const el = span(diffClass(m), m.slug);

    if (m.locked) {
      el.append(' ', ...lockIcon());
    }

    return el;
  };

  const ps1 = () => node('span', 't-ps1', node('b', null, 'ander@kali'), ':', node('em', null, '~'), '$');
  const echo = (text) => emit(node('div', 't-line t-cmd', ps1(), ' ', span('t-typed', text)));

  const toBottom = () => {
    body.scrollTop = body.scrollHeight;
  };

  /* After a command: if its output (from the echoed command down to the
     prompt) is taller than the window, show it from the top rather than
     leaving its first lines scrolled away. */
  const showFrom = (first) => {
    if (!first || !first.isConnected) {
      toBottom();
      return;
    }

    const top = first.getBoundingClientRect().top - body.getBoundingClientRect().top + body.scrollTop;

    if (body.scrollHeight - top > body.clientHeight) {
      body.scrollTop = Math.max(0, top - 6);
    } else {
      toBottom();
    }
  };

  /* Run a line typed at the prompt (or by a chip), then scroll to it. */
  const exec = (raw) => {
    const before = log.lastElementChild;
    run(raw);
    showFrom(before ? before.nextElementSibling : log.firstElementChild);
  };

  /* Edit distance for "did you mean" (optimal string alignment: a swapped
     pair of letters, as in "hlep", counts as one edit). */
  const distance = (a, b) => {
    const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);

    for (let j = 1; j <= b.length; j++) {
      d[0][j] = j;
    }

    for (let i = 1; i <= a.length; i++) {
      for (let j = 1; j <= b.length; j++) {
        const cost = a[i - 1] === b[j - 1] ? 0 : 1;
        d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);

        if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
          d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
        }
      }
    }

    return d[a.length][b.length];
  };

  const closest = (word, pool) => {
    const w = word.toLowerCase();
    const limit = w.length <= 4 ? 1 : 2;
    let best = null;
    let bestD = Infinity;

    pool.forEach((p) => {
      const d = distance(w, p.toLowerCase());

      if (d < bestD) {
        best = p;
        bestD = d;
      }
    });

    return bestD <= limit ? best : null;
  };

  const suggest = (word, pool) => {
    const guess = closest(word, pool);

    if (guess) {
      note(t(`did you mean ${guess}?`, `¿querías decir ${guess}?`));
    }
  };

  const noSuchFile = (cmd, arg, pool) => {
    line('t-err', `${cmd}: ${arg}: ${t('No such file or directory', 'No existe el fichero o el directorio')}`);
    suggest(arg, pool);
  };

  const denied = (cmd, arg) => line('t-err', `${cmd}: ${arg}: ${t('Permission denied', 'Permiso denegado')}`);

  const go = (href, label) => {
    line('t-dim', '→ ', t('opening ', 'abriendo '), span('t-hi', label), '…');
    window.setTimeout(() => window.location.assign(href), REDUCED ? 150 : 450);
  };

  const count = (pred) => machines.filter(pred).length;

  const since = () => {
    const oldest = machines[machines.length - 1];

    if (!oldest) {
      return '';
    }

    const [y, m] = oldest.date.split('-').map(Number);
    return new Intl.DateTimeFormat(ES ? 'es' : 'en', { month: 'short', year: 'numeric' }).format(new Date(y, m - 1, 1));
  };

  /* ---- Commands ----------------------------------------------------------- */

  const HELP = [
    ['whoami', t('who I am', 'quién soy')],
    ['about', t('a short bio', 'una presentación breve')],
    ['neofetch', t('the system at a glance', 'el sistema de un vistazo')],
    ['ls [dir]', t('list files, machines, cves, projects', 'lista ficheros, machines, cves, projects')],
    [t('cat <machine>', 'cat <máquina>'), t('a writeup in three lines', 'un writeup en tres líneas')],
    [t('open <name>', 'open <nombre>'), t('open a writeup or a project', 'abre un writeup o un proyecto')],
    [t('cd <page>', 'cd <página>'), t('go to machines, cves, projects, archive', 've a machines, cves, projects, archive')],
    ['stats', t('writeups by difficulty and system', 'writeups por dificultad y sistema')],
    ['certs', t('certifications and education', 'certificaciones y formación')],
    ['contact', t('how to reach me', 'cómo contactarme')],
    ['clear', t('clear the screen', 'limpia la pantalla')]
  ];

  function help() {
    grid('t-kv', HELP.map(([cmd, desc]) => [span('t-ok', cmd), span('t-dim', desc)]));
    blank();
    note(t('Tab completes · ↑ ↓ history', 'Tab autocompleta · ↑ ↓ historial'));
    note(t('psst: there is a flag hidden on this box. stuck? hint', 'psst: hay una flag escondida en esta máquina. ¿atascado? hint'));
  }

  function whoami() {
    line('t-hi', 'ander');
    line(
      't-dim',
      t(
        'offensive security · Computer Engineer · MSc in Cybersecurity',
        'seguridad ofensiva · Ingeniero Informático · Máster en Ciberseguridad'
      )
    );
  }

  function about() {
    line(
      null,
      t(
        "Hi, I'm Ander. I break into machines and document exactly how.",
        'Hola, soy Ander: comprometo máquinas y documento exactamente cómo.'
      )
    );
    line(
      null,
      t(
        `Computer Engineer with an MSc in Cybersecurity. ${machines.length} writeups so far, recon to root, with the reasoning behind every step.`,
        `Ingeniero Informático con un Máster en Ciberseguridad. ${machines.length} writeups hasta ahora, del reconocimiento al root, con el razonamiento de cada paso.`
      )
    );

    const next = certs.find((c) => !c.done);

    if (next) {
      line(
        null,
        t(`Right now: preparing the ${next.name} (exam ${next.when}).`, `Ahora mismo: preparando el ${next.name} (examen ${next.when}).`)
      );
    }

    note(t('cd machines · cat <machine> · contact', 'cd machines · cat <máquina> · contact'));
  }

  function neofetch() {
    const info = node('div', 't-fetch-info');
    const row = (key, value) => info.append(node('div', null, span('t-ok t-b', key), ': ', value));

    info.append(node('div', 't-hi t-b', 'ander@kali'), node('div', 't-dim', '-'.repeat(10)));
    row('OS', 'Kali GNU/Linux');
    row(t('Role', 'Rol'), t('offensive security', 'seguridad ofensiva'));
    row(t('Education', 'Formación'), t('MSc Cybersecurity', 'Máster en Ciberseguridad'));

    if (certs.length) {
      row('Certs', certs.map((c) => (c.done ? `${c.name} ✓` : `${c.name} · ${t('exam', 'examen')} ${c.when}`)).join(' · '));
    }

    row('Writeups', machines.length);
    row('CVEs', cveList().length);
    row(t('Projects', 'Proyectos'), projects.length);
    row('Uptime', t(`since ${since()}`, `desde ${since()}`));

    const swatches = node('div', 't-swatches');
    ['#484f58', '#ff7b72', '#3fb950', '#d29922', '#58a6ff', '#bc8cff', '#39c5cf', '#e6edf3'].forEach((c) => {
      const s = node('span', null);
      s.style.background = c;
      swatches.append(s);
    });
    info.append(swatches);

    emit(node('div', 't-fetch', node('pre', 't-logo', logo), info));
  }

  function lsHome(all, long) {
    const entries = [
      ...(all
        ? [
            { name: '.', dir: true, perm: 'drwxr-xr-x', owner: 'ander' },
            { name: '..', dir: true, perm: 'drwxr-xr-x', owner: 'root' },
            { name: '.flag', perm: '-r--------', owner: 'root', flag: true }
          ]
        : []),
      ...FILES.map((f) => ({ name: f, perm: '-rw-r--r--', owner: 'ander' })),
      ...DIRS.map((d) => ({ name: `${d}/`, dir: true, perm: 'drwxr-xr-x', owner: 'ander' }))
    ];

    const label = (e) => span(e.dir ? 't-dir' : e.flag ? 't-warn t-b' : null, e.name);

    if (long) {
      grid('t-table t-cols-3', entries.map((e) => [span('t-dim', e.perm), span('t-dim', e.owner), label(e)]));
    } else {
      grid('t-cols', entries.map(label));
    }

    if (all) {
      state.sawFlag = true;
    }
  }

  function lsMachines(long) {
    if (long) {
      grid(
        't-table t-cols-4',
        machines.map((m) => [machineName(m), span(diffClass(m), m.diff), span(null, cap(m.os)), span('t-dim', m.platform)])
      );
    } else {
      grid('t-cols', machines.map(machineName));
    }

    line(
      't-dim',
      ...LEVELS.flatMap((lv, i) => [i ? ' · ' : '', span(`t-${lv.toLowerCase()}`, lv.toLowerCase())]),
      '   ',
      ...lockIcon(),
      t(' active machine', ' máquina activa')
    );
    note(t('cat <name> for a summary · open <name> to read it', 'cat <nombre> para un resumen · open <nombre> para leerlo'));
  }

  function lsCves() {
    const list = cveList();
    grid('t-cols t-cols-wide', list.map((c) => span('t-warn', c)));
    note(`${list.length} CVEs · cd cves`);
  }

  function lsProjects() {
    grid('t-cols t-cols-wide', projects.map((p) => span('t-dir', `${p.slug}/`)));
    note(t('open <project> · cd projects', 'open <proyecto> · cd projects'));
  }

  function lsArchive() {
    const years = {};
    machines.forEach((m) => {
      const y = m.date.slice(0, 4);
      years[y] = (years[y] || 0) + 1;
    });
    grid(
      't-cols',
      Object.keys(years)
        .sort()
        .reverse()
        .map((y) => node('span', null, span('t-dir', `${y}/`), span('t-dim', ` ${years[y]}`)))
    );
    note('cd archive');
  }

  function ls(args) {
    const flags = args.filter((a) => a.startsWith('-')).join('');
    const target = (args.find((a) => !a.startsWith('-')) || '')
      .replace(/^~\/?/, '')
      .replace(/^\.\//, '')
      .replace(/\/+$/, '')
      .toLowerCase();

    if (target === '' || target === '.' || target === '/home/ander') {
      lsHome(flags.includes('a'), flags.includes('l'));
    } else if (target === 'machines' || target === 'writeups') {
      lsMachines(flags.includes('l'));
    } else if (target === 'cves') {
      lsCves();
    } else if (target === 'projects') {
      lsProjects();
    } else if (target === 'archive') {
      lsArchive();
    } else if (FILES.includes(target)) {
      line(null, target);
    } else if (isFlagPath(target)) {
      state.sawFlag = true;
      line('t-warn t-b', '.flag');
    } else {
      line(
        't-err',
        t(`ls: cannot access '${target}': No such file or directory`, `ls: no se puede acceder a '${target}': No existe el fichero o el directorio`)
      );
      suggest(target, [...DIRS, ...FILES]);
    }
  }

  function catMachine(m) {
    line(
      null,
      span('t-hi t-b', m.title),
      '  ',
      span(diffClass(m), m.diff),
      span('t-dim', ` · ${[cap(m.os), m.platform, m.date].filter(Boolean).join(' · ')}`)
    );

    if (m.locked) {
      line(
        't-warn',
        ...lockIcon(false),
        ' ',
        t('Protected: an active machine, published once it retires.', 'Protegido: una máquina activa, se publica cuando se retire.')
      );
    } else {
      if (m.cves.length) {
        line('t-warn', m.cves.join(' · '));
      }

      if (m.summary) {
        line(null, wholeSentences(m.summary));
      }
    }

    note(`open ${m.slug}`);
  }

  function cat(args) {
    if (!args.length) {
      line('t-dim', t('usage: cat <machine> (Tab completes the name)', 'uso: cat <máquina> (Tab completa el nombre)'));
      return;
    }

    args.forEach((raw) => {
      const a = raw.replace(/^~\//, '').replace(/^\.\//, '');

      if (a === 'about.txt') {
        about();
      } else if (a === 'certs.txt') {
        certsCmd();
      } else if (a === 'contact.txt') {
        contact();
      } else if (isFlagPath(raw) || a === '.flag') {
        state.sawFlag = true;
        state.denied = true;
        denied('cat', raw);
      } else if (DIRS.includes(a.replace(/\/+$/, ''))) {
        line('t-err', `cat: ${raw}: ${t('Is a directory', 'Es un directorio')}`);
      } else {
        const m = findMachine(a);

        if (m) {
          catMachine(m);
        } else {
          noSuchFile('cat', raw, [...machineNames(), ...FILES]);
        }
      }
    });
  }

  function open(args) {
    const a = (args[0] || '').toLowerCase().replace(/\/+$/, '');

    if (!a) {
      line('t-dim', t('usage: open <machine|project>', 'uso: open <máquina|proyecto>'));
      return;
    }

    const target = findMachine(a) || projects.find((p) => p.slug === a || p.title.toLowerCase() === a);

    if (target) {
      go(target.href, target.title);
    } else if (pages[a]) {
      go(pages[a], `${a}/`);
    } else {
      line('t-err', `open: ${a}: ${t('not found', 'no encontrado')}`);
      suggest(a, [...machineNames(), ...projects.map((p) => p.slug)]);
    }
  }

  function cd(args) {
    const raw = args[0] || '~';
    const a = raw.replace(/^~\//, '').replace(/\/+$/, '').toLowerCase();

    if (a === '~' || a === '' || a === '.' || a === '/home/ander') {
      return;
    }

    if (a === '..' || a.startsWith('/')) {
      denied('cd', raw);
      return;
    }

    const key = a === 'writeups' ? 'machines' : a;
    const m = findMachine(a);

    if (pages[key]) {
      go(pages[key], `${key}/`);
    } else if (m) {
      go(m.href, m.title);
    } else {
      noSuchFile('cd', raw, DIRS);
    }
  }

  function stats() {
    line('t-hi', `${machines.length} writeups · ${cveList().length} CVEs · ${projects.length} ${t('projects', 'proyectos')}`);

    const bars = (rows, cls) => {
      const max = Math.max(1, ...rows.map(([, n]) => n));
      grid(
        't-kv',
        rows.map(([label, n, c]) => [
          span(c || cls, label),
          node('span', null, span(`${c || cls} t-bar`, '█'.repeat(Math.max(n ? 1 : 0, Math.round((n / max) * 16)))), ' ', span('t-hi', n))
        ])
      );
    };

    bars(LEVELS.map((lv) => [lv.toLowerCase(), count((m) => m.diff === lv), `t-${lv.toLowerCase()}`]));
    bars(SYSTEMS.map((os) => [os, count((m) => m.os === os)]), 't-dir');
  }

  function certsCmd() {
    certs.forEach((c) => {
      line(null, span(c.done ? 't-ok' : 't-warn', c.done ? '✓ ' : '◔ '), span('t-hi t-b', c.name), span('t-dim', ` · ${c.full} (${c.issuer})`));
      line(
        't-indent',
        c.done ? t(`certified · ${c.when}`, `certificado · ${c.when}`) : t(`in progress · exam ${c.when}`, `en preparación · examen ${c.when}`)
      );
    });
    line(null, span('t-ok', '✓ '), span('t-hi t-b', t('MSc in Cybersecurity', 'Máster en Ciberseguridad')));
    line(null, span('t-ok', '✓ '), span('t-hi t-b', t('Computer Engineering degree', 'Grado en Ingeniería Informática')));
  }

  function contact() {
    grid('t-kv', contacts.map((c) => [span('t-ok', c.name), link(c.href, c.text)]));
    note(t('open to pentesting & offensive security roles. let’s talk', 'abierto a puestos de pentesting y seguridad ofensiva. hablemos'));
  }

  function clear() {
    if (intro) {
      intro.hidden = true;
    }

    log.replaceChildren();
  }

  function historyCmd() {
    grid('t-kv', state.history.map((h, i) => [span('t-dim', i + 1), span(null, h)]));
  }

  function hint() {
    if (state.solved) {
      note(t('you already have it: send it over (contact)', 'ya la tienes: mándamela (contact)'));
    } else if (state.gotB64) {
      note(t('almost there: pipe it into base64 -d, or submit <flag>', 'casi: pásalo por base64 -d, o submit <flag>'));
    } else if (state.sudoList) {
      note(t('GTFOBins: base64 reads any file it may, so run it with sudo', 'GTFOBins: base64 lee cualquier fichero al que tenga acceso, así que ejecútalo con sudo'));
    } else if (state.sawFlag || state.denied) {
      note(t('.flag belongs to root. what may you run as root? (sudo -l)', '.flag es de root. ¿qué puedes ejecutar como root? (sudo -l)'));
    } else {
      note(t('not everything shows up with a plain ls. try ls -la', 'no todo aparece con un ls normal. prueba ls -la'));
    }
  }

  function pwned() {
    const first = !state.solved;
    state.solved = true;

    line('t-ok t-b', FLAG);
    line('t-ok', t('🏁 root-owned flag captured. nice work.', '🏁 flag de root capturada. buen trabajo.'));

    const mail = contacts.find((c) => c.name === 'email');

    if (mail) {
      const subject = encodeURIComponent(`${FLAG} · ${t('found it on your site', 'encontrada en tu web')}`);
      line(null, t('send it to me and let’s talk: ', 'mándamela y hablamos: '), link(`${mail.href}?subject=${subject}`, mail.text));
    }

    if (first && !REDUCED) {
      term.classList.remove('is-pwned');
      void term.offsetWidth; /* restart the glow */
      term.classList.add('is-pwned');
    }
  }

  function decode(data) {
    let text;

    try {
      text = window.atob(data.trim());
    } catch (e) {
      line('t-err', t('base64: invalid input', 'base64: entrada no válida'));
      return;
    }

    if (text === FLAG) {
      pwned();
    } else {
      line(null, text);
    }
  }

  function sudo(args) {
    if (!args.length) {
      line('t-dim', t('usage: sudo -l | sudo <command>', 'uso: sudo -l | sudo <comando>'));
      return;
    }

    if (args[0] === '-l' || args[0] === '--list') {
      state.sudoList = true;
      line(null, t('Matching Defaults entries for ander on kali:', 'Entradas de Defaults coincidentes para ander en kali:'));
      line('t-indent t-dim', 'env_reset, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin');
      blank();
      line(null, t('User ander may run the following commands on kali:', 'El usuario ander puede ejecutar los siguientes comandos en kali:'));
      line('t-indent t-hi', '(root) NOPASSWD: /usr/bin/base64');
      return;
    }

    const bin = args[0].replace(/^\/usr\/bin\//, '');

    if (bin === 'base64') {
      const decodeFlag = args.includes('-d') || args.includes('--decode');
      const file = args.slice(1).find((a) => !a.startsWith('-'));

      if (!file) {
        line('t-dim', t('usage: sudo base64 <file>', 'uso: sudo base64 <fichero>'));
      } else if (isFlagPath(file) && !decodeFlag) {
        state.gotB64 = true;
        line('t-hi', FLAG_B64);
      } else if (isFlagPath(file)) {
        line('t-err', t('base64: invalid input', 'base64: entrada no válida'));
      } else {
        noSuchFile('base64', file, ['.flag']);
      }

      return;
    }

    line(
      't-err',
      t(
        `Sorry, user ander is not allowed to execute '/usr/bin/${args.join(' ')}' as root on kali.`,
        `Lo siento, el usuario ander no tiene permiso para ejecutar '/usr/bin/${args.join(' ')}' como root en kali.`
      )
    );
  }

  function base64(args) {
    const file = args.find((a) => !a.startsWith('-'));

    if (args.includes('-d') || args.includes('--decode')) {
      line('t-dim', t('usage: echo <text> | base64 -d', 'uso: echo <texto> | base64 -d'));
    } else if (!file) {
      line('t-dim', t('usage: base64 <file>', 'uso: base64 <fichero>'));
    } else if (isFlagPath(file)) {
      state.sawFlag = true;
      state.denied = true;
      denied('base64', file);
    } else {
      noSuchFile('base64', file, ['.flag']);
    }
  }

  /* The one pipeline this box supports: <something> | base64 -d. */
  function pipe(segments) {
    const [left, right] = segments;

    if (segments.length !== 2 || !/^base64\s+(-d|--decode)$/.test(right)) {
      line('t-err', t('zsh: that pipeline is not supported here', 'zsh: esa tubería no está soportada aquí'));
      return;
    }

    const words = left.split(/\s+/);
    const head = words[0].toLowerCase();

    if (head === 'echo') {
      decode(words.slice(1).join(' ').replace(/^["']|["']$/g, ''));
    } else if (head === 'sudo' && (words[1] || '').replace(/^\/usr\/bin\//, '') === 'base64' && isFlagPath(words[2] || '')) {
      state.gotB64 = true;
      decode(FLAG_B64);
    } else if ((head === 'cat' || head === 'base64') && isFlagPath(words[1] || '')) {
      state.sawFlag = true;
      state.denied = true;
      denied(head, words[1]);
    } else {
      run(left, true);
    }
  }

  function submit(args) {
    const guess = args.join(' ').trim();

    if (!guess) {
      line('t-dim', t('usage: submit <flag>', 'uso: submit <flag>'));
    } else if (guess === FLAG) {
      pwned();
    } else {
      line('t-err', t('nope, that is not the flag (hint)', 'no, esa no es la flag (hint)'));
    }
  }

  function nmap() {
    line(null, 'Starting Nmap 7.95 ( https://nmap.org )');
    line(null, 'Nmap scan report for andermonreal.github.io');
    grid('t-table t-cols-4', [
      [span('t-hi', 'PORT'), span('t-hi', 'STATE'), span('t-hi', 'SERVICE'), span(null, '')],
      [span(null, '443/tcp'), span('t-ok', 'open'), span(null, 'https'), span('t-dim', t('← you are here', '← estás aquí'))],
      [span(null, '25/tcp'), span('t-ok', 'open'), span(null, 'smtp'), span('t-dim', t('← try contact', '← prueba contact'))],
      [span(null, '1337/tcp'), span('t-ok', 'open'), span(null, 'flag?'), span('t-dim', t('← try hint', '← prueba hint'))]
    ]);
    line('t-dim', 'Nmap done: 1 IP address (1 host up) scanned in 0.42 seconds');
  }

  function rm(args) {
    const target = args.filter((a) => !a.startsWith('-')).join(' ');
    const recursive = args.some((a) => /^-[a-z]*r/i.test(a));

    if (recursive && ['/', '/*', '~', '*', '.'].includes(target)) {
      line('t-err', t(`rm: it is dangerous to operate recursively on '${target}'`, `rm: es peligroso operar recursivamente sobre '${target}'`));
      line('t-err', t('rm: use --no-preserve-root to override this failsafe', 'rm: use --no-preserve-root para inhibir esta medida de seguridad'));
      note(t('nice try', 'buen intento'));
    } else {
      line('t-err', `rm: ${t('cannot remove', 'no se puede borrar')} '${target || '?'}': ${t('Permission denied', 'Permiso denegado')}`);
    }
  }

  const COMMANDS = {
    help,
    ayuda: help,
    '?': help,
    whoami,
    about,
    neofetch,
    fastfetch: neofetch,
    ls,
    ll: (args) => ls(['-la', ...args]),
    dir: ls,
    cat,
    less: cat,
    more: cat,
    open,
    cd,
    stats,
    certs: certsCmd,
    contact,
    contacto: contact,
    hire: contact,
    'hire-me': contact,
    clear,
    cls: clear,
    history: historyCmd,
    hint,
    pista: hint,
    sudo,
    base64,
    submit,
    nmap,
    rm,
    pwd: () => line(null, '/home/ander'),
    id: () => line(null, 'uid=1000(ander) gid=1000(ander) groups=1000(ander)'),
    hostname: () => line(null, 'kali'),
    uname: (args) =>
      line(null, args.includes('-a') ? 'Linux kali 6.12.20-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.12.20-1kali1 x86_64 GNU/Linux' : 'Linux'),
    date: () => line(null, new Date().toString().replace(/\s*\(.*\)$/, '')),
    echo: (args) => line(null, args.join(' ').replace(/^["']|["']$/g, '') || '\u00a0'),
    man: (args) => {
      line('t-err', t(`No manual entry for ${args[0] || 'that'}`, `No hay ninguna entrada de manual para ${args[0] || 'eso'}`));
      note(t('try help', 'prueba help'));
    },
    exit: () => {
      line(null, 'logout');
      note(t('nice try: this terminal is not going anywhere. help?', 'buen intento: esta terminal no se va a ninguna parte. ¿help?'));
    },
    vim: () => note(t('no editors on this box: cat is all you need', 'no hay editores en esta máquina: con cat te basta'))
  };

  ['logout', 'quit'].forEach((c) => {
    COMMANDS[c] = COMMANDS.exit;
  });
  ['vi', 'nano', 'emacs', 'code'].forEach((c) => {
    COMMANDS[c] = COMMANDS.vim;
  });

  /* What Tab completes, and what "did you mean" suggests. */
  const COMPLETE = ['help', 'whoami', 'about', 'neofetch', 'ls', 'cat', 'open', 'cd', 'stats', 'certs', 'contact', 'clear', 'history', 'hint', 'sudo', 'submit', 'echo'];

  const ARGS = {
    cat: () => [...FILES, ...machineNames()],
    less: () => [...FILES, ...machineNames()],
    open: () => [...machineNames(), ...projects.map((p) => p.slug)],
    cd: () => DIRS.map((d) => `${d}/`),
    ls: () => [...DIRS.map((d) => `${d}/`), '-la'],
    man: () => COMPLETE
  };

  function run(raw, fromPipe) {
    const text = raw.trim();

    if (!fromPipe) {
      echo(raw);
    }

    if (!text) {
      return;
    }

    if (!fromPipe) {
      state.history.push(text);
      state.cursor = state.history.length;
    }

    if (text === FLAG) {
      pwned();
      return;
    }

    if (!fromPipe && text.includes('|')) {
      pipe(text.split('|').map((s) => s.trim()));
      return;
    }

    const [head, ...args] = text.split(/\s+/);
    const fn = Object.prototype.hasOwnProperty.call(COMMANDS, head.toLowerCase()) ? COMMANDS[head.toLowerCase()] : null;

    if (fn) {
      fn(args);
      return;
    }

    line('t-err', ES ? `zsh: orden no encontrada: ${head}` : `zsh: command not found: ${head}`);

    if (!closest(head, COMPLETE)) {
      note(t('type help for the list', 'escribe help para ver la lista'));
    } else {
      suggest(head, COMPLETE);
    }
  }

  /* ---- Tab completion and history ------------------------------------------ */

  const commonPrefix = (words) =>
    words.reduce((prefix, w) => {
      let i = 0;

      while (i < prefix.length && i < w.length && prefix[i].toLowerCase() === w[i].toLowerCase()) {
        i++;
      }

      return prefix.slice(0, i);
    });

  /* Returns true when it handled the key; with nothing to complete, Tab keeps
     moving focus as usual, so the keyboard is never trapped here. */
  function complete() {
    const value = input.value;
    const parts = value.split(' ');
    const partial = parts[parts.length - 1];
    let pool;

    if (!value.trim()) {
      return false;
    }

    if (parts.length === 1) {
      pool = COMPLETE;
    } else if (parts[0].toLowerCase() === 'sudo') {
      pool = parts.length === 2 ? ['-l', 'base64'] : ['.flag'];
    } else if (parts[0].toLowerCase() === 'base64') {
      pool = ['.flag'];
    } else {
      const fn = ARGS[parts[0].toLowerCase()];
      pool = fn ? fn() : [];
    }

    const low = partial.toLowerCase();
    const matches = pool.filter((c) => c.toLowerCase().startsWith(low));

    if (!matches.length) {
      return false;
    }

    if (matches.length === 1) {
      parts[parts.length - 1] = matches[0];
      input.value = parts.join(' ') + (matches[0].endsWith('/') ? '' : ' ');
      state.tabs = 0;
      return true;
    }

    const prefix = commonPrefix(matches);

    if (prefix.length > partial.length) {
      parts[parts.length - 1] = prefix;
      input.value = parts.join(' ');
      state.tabs = 0;
      return true;
    }

    state.tabs += 1;

    if (state.tabs >= 2) {
      echo(value);
      grid('t-cols', matches.map((m) => span(null, m)));
      toBottom();
      state.tabs = 0;
    }

    return true;
  }

  function historyStep(dir) {
    const h = state.history;

    if (!h.length) {
      return;
    }

    state.cursor = Math.min(h.length, Math.max(0, state.cursor + dir));
    input.value = h[state.cursor] || '';
    window.requestAnimationFrame(() => input.setSelectionRange(input.value.length, input.value.length));
  }

  /* ---- The intro, then the live prompt ------------------------------------- */

  const introLines = intro ? Array.from(intro.querySelectorAll('.t-line')) : [];
  let introTimer = null;
  let ready = false;

  function finishIntro() {
    if (ready) {
      return;
    }

    ready = true;
    window.clearTimeout(introTimer);

    introLines.forEach((l) => {
      const typed = l.querySelector('.t-typed');

      if (typed && typed.dataset.text) {
        typed.textContent = typed.dataset.text;
      }

      l.classList.remove('is-current');
      l.classList.add('is-shown');
    });

    form.classList.add('is-shown');
    term.classList.remove('is-typing');
    toBottom();
  }

  function playIntro() {
    if (!term.classList.contains('is-typing')) {
      finishIntro();
      return;
    }

    const lines = [...introLines, form];
    let i = 0;

    const next = () => {
      if (i >= lines.length) {
        finishIntro();
        return;
      }

      const l = lines[i++];
      const typed = l.querySelector('.t-typed');
      l.classList.add('is-shown');

      if (!typed) {
        introTimer = window.setTimeout(next, l.classList.contains('t-out') ? 120 : 0);
        return;
      }

      const text = typed.dataset.text || typed.textContent;
      let k = 0;
      typed.dataset.text = text;
      typed.textContent = '';
      l.classList.add('is-current');

      const tick = () => {
        typed.textContent = text.slice(0, ++k);

        if (k < text.length) {
          introTimer = window.setTimeout(tick, 35 + Math.random() * 45);
        } else {
          l.classList.remove('is-current');
          introTimer = window.setTimeout(next, 280);
        }
      };

      introTimer = window.setTimeout(tick, 420);
    };

    introTimer = window.setTimeout(next, 350);
  }

  /* ---- Wiring -------------------------------------------------------------- */

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    const value = input.value;
    input.value = '';
    state.tabs = 0;
    exec(value);
  });

  input.addEventListener('keydown', (event) => {
    if (event.key === 'Tab' && !event.shiftKey && !event.altKey && !event.ctrlKey && !event.metaKey) {
      if (complete()) {
        event.preventDefault();
      }

      return;
    }

    state.tabs = 0;

    if (event.key === 'ArrowUp') {
      event.preventDefault();
      historyStep(-1);
    } else if (event.key === 'ArrowDown') {
      event.preventDefault();
      historyStep(1);
    } else if (event.key === 'Escape') {
      input.value = '';
    } else if (event.ctrlKey && event.key.toLowerCase() === 'l') {
      event.preventDefault();
      clear();
    } else if (event.ctrlKey && event.key.toLowerCase() === 'c' && input.selectionStart === input.selectionEnd) {
      event.preventDefault();
      echo(`${input.value}^C`);
      input.value = '';
      toBottom();
    }
  });

  /* A click anywhere in the window types into it, unless it is on a link or
     a button, or it ends a text selection. */
  term.addEventListener('click', (event) => {
    if (event.target.closest('a, button') || String(window.getSelection ? window.getSelection() : '')) {
      return;
    }

    finishIntro();
    input.focus({ preventScroll: true });
  });

  /* The command chips (for touch screens, and for the curious): they type
     their command into the prompt and run it. */
  let busy = false;

  chips.forEach((chip) =>
    chip.addEventListener('click', () => {
      const cmd = chip.dataset.cmd;

      if (busy || !cmd) {
        return;
      }

      finishIntro();

      if (REDUCED) {
        exec(cmd);
        return;
      }

      busy = true;
      let k = 0;

      const tick = () => {
        input.value = cmd.slice(0, ++k);

        if (k < cmd.length) {
          window.setTimeout(tick, 28);
        } else {
          window.setTimeout(() => {
            input.value = '';
            exec(cmd);
            busy = false;
          }, 140);
        }
      };

      tick();
    })
  );

  /* For whoever opens the developer tools. */
  if (window.console && typeof window.console.log === 'function') {
    window.console.log(
      '%c ander@kali %c ' +
        t(
          'Reading the source? There is a flag hidden in the terminal on the home page. Start with: ls -la',
          '¿Curioseando el código? Hay una flag escondida en la terminal de la portada. Empieza por: ls -la'
        ),
      'background:#9fef00;color:#0d1117;font-weight:700;border-radius:3px;padding:1px 3px',
      'color:inherit'
    );
  }

  playIntro();
})();
