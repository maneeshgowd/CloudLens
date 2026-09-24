'use strict';
const pptxgen = require('pptxgenjs');

const pptx = new pptxgen();
pptx.layout = 'LAYOUT_WIDE'; // 13.33 × 7.5 inches

// ── Colour palette — light theme ──────────────────────────────────────────────
const C = {
  bg:     'FFFFFF',  // white slide background
  surf:   'F8FAFC',  // light gray card fill
  text:   '1E293B',  // dark body text
  muted:  '475569',  // secondary text
  border: 'CBD5E1',  // card border
  header: '1E3A8A',  // navy header bar
  blue:   '2563EB',
  sky:    '38BDF8',
  aws:    'FF9900',
  green:  '16A34A',
  red:    'DC2626',
  orange: 'EA580C',
  purple: '7C3AED',
  yellow: 'CA8A04',
  white:  'FFFFFF',
  dark:   '0F172A',
};

// Tinted card backgrounds (light version of each accent)
const TINT = {
  [C.blue]:   'EFF6FF',
  [C.red]:    'FEF2F2',
  [C.green]:  'F0FDF4',
  [C.purple]: 'F5F3FF',
  [C.orange]: 'FFF7ED',
  [C.aws]:    'FFFBEB',
};

const W = 13.33;
const H = 7.5;

// ── Helpers ───────────────────────────────────────────────────────────────────

function bg(s) {
  s.addShape('rect', { x:0, y:0, w:W, h:H, fill:{ color:C.bg }, line:{ color:C.bg } });
}

// Dark navy header bar — white text reads well on it
function header(s, title, sub = '') {
  s.addShape('rect', { x:0, y:0, w:W, h:1.12, fill:{ color:C.header }, line:{ color:C.header } });
  s.addShape('rect', { x:0, y:0, w:0.07, h:1.12, fill:{ color:C.aws }, line:{ color:C.aws } });
  s.addText(title, { x:0.28, y:0.1, w:W-0.56, h:0.55, fontSize:22, bold:true, color:C.white, fontFace:'Segoe UI' });
  if (sub) s.addText(sub, { x:0.28, y:0.65, w:W-0.56, h:0.32, fontSize:11, color:'93C5FD', fontFace:'Segoe UI' });
}

function footer(s) {
  s.addShape('rect', { x:0, y:H-0.26, w:W, h:0.26, fill:{ color:C.surf }, line:{ color:C.border } });
  s.addText('CloudLens  ·  Multi-Cloud Operational Intelligence', {
    x:0, y:H-0.24, w:W, h:0.22, fontSize:7.5, color:C.muted, fontFace:'Segoe UI', align:'center',
  });
}

// Plain box with border
function box(s, x, y, w, h, fill, border) {
  s.addShape('rect', { x, y, w, h, fill:{ color:fill }, line:{ color:border, width:0.75 } });
}

// Card with a coloured top bar
function card(s, x, y, w, h, accentColor) {
  box(s, x, y, w, h, TINT[accentColor] || C.surf, accentColor);
  s.addShape('rect', { x, y, w, h:0.06, fill:{ color:accentColor }, line:{ color:accentColor } });
}

// Card with a thin coloured left strip
function accentCard(s, x, y, w, h, accentColor) {
  box(s, x, y, w, h, C.surf, accentColor);
  s.addShape('rect', { x, y, w:0.06, h, fill:{ color:accentColor }, line:{ color:accentColor } });
}

function dot(s, x, y, color) {
  s.addShape('ellipse', { x, y, w:0.12, h:0.12, fill:{ color }, line:{ color } });
}

function arrow(s, x, y, w) {
  s.addShape('rect', { x, y:y+0.05, w, h:0.05, fill:{ color:C.border }, line:{ color:C.border } });
  s.addText('▶', { x:x+w-0.06, y:y, w:0.22, h:0.2, fontSize:9, color:C.border, fontFace:'Segoe UI' });
}

// ── SLIDE 1 — Title ───────────────────────────────────────────────────────────
(function () {
  const s = pptx.addSlide();
  bg(s);

  // Top navy band
  s.addShape('rect', { x:0, y:0, w:W, h:3.0, fill:{ color:C.header }, line:{ color:C.header } });
  s.addShape('rect', { x:0, y:0, w:0.12, h:3.0, fill:{ color:C.aws }, line:{ color:C.aws } });

  s.addText(
    [{ text:'Cloud', options:{ color:C.white, bold:true } },
     { text:'Lens',  options:{ color:'93C5FD', bold:true } }],
    { x:0.45, y:0.4, w:10, h:1.45, fontSize:68, fontFace:'Segoe UI' }
  );

  s.addText('Multi-Cloud Operational Intelligence', {
    x:0.45, y:1.75, w:W-0.9, h:0.55, fontSize:20, color:'93C5FD', fontFace:'Segoe UI',
  });

  s.addText('"Finding failures your cloud provider doesn\'t surface."', {
    x:0.45, y:3.2, w:W-0.9, h:0.6, fontSize:18, color:C.text, fontFace:'Segoe UI', italic:true,
  });

  s.addText('AWS  ·  Azure  ·  Read-Only  ·  Zero Risk to Production', {
    x:0.45, y:4.05, w:W-0.9, h:0.4, fontSize:13, color:C.muted, fontFace:'Segoe UI',
  });

  footer(s);
})();

// ── SLIDE 2 — The Problem ─────────────────────────────────────────────────────
(function () {
  const s = pptx.addSlide();
  bg(s);
  header(s, 'The Problem', 'Cloud environments grow silently broken');

  const points = [
    {
      color: C.blue,
      label: 'Cloud monitoring tools don\'t talk to each other',
      desc:  'AWS has Trusted Advisor for cost, Security Hub for vulnerabilities, CloudWatch for metrics — all separate, with no single view across them.',
    },
    {
      color: C.red,
      label: 'Broken automated workflows trigger no alerts',
      desc:  'A scheduled job (EventBridge rule) can silently stop delivering work to its target function (Lambda) for weeks — no alarm fires, no one notices.',
    },
    {
      color: C.orange,
      label: 'Security risks hide in deployed code',
      desc:  'Functions on outdated software versions (runtimes) accumulate unpatched security holes. Abandoned functions still hold active access permissions (IAM roles).',
    },
  ];

  points.forEach((p, i) => {
    const y = 1.35 + i * 1.62;
    accentCard(s, 0.45, y, W-0.9, 1.38, p.color);
    s.addText(p.label, { x:0.72, y:y+0.18, w:W-1.4, h:0.42, fontSize:15, bold:true, color:p.color, fontFace:'Segoe UI' });
    s.addText(p.desc,  { x:0.72, y:y+0.66, w:W-1.4, h:0.58, fontSize:12, color:C.muted, fontFace:'Segoe UI' });
  });

  footer(s);
})();

// ── SLIDE 3 — What is CloudLens? ──────────────────────────────────────────────
(function () {
  const s = pptx.addSlide();
  bg(s);
  header(s, 'What is CloudLens?', 'One command — full picture');

  // Command line
  box(s, 0.45, 1.2, W-0.9, 0.62, C.dark, C.green);
  s.addText('$ node cloudlens.js  --provider aws  --region us-east-1  --days 7', {
    x:0.6, y:1.28, w:W-1.2, h:0.42,
    fontSize:13, color:'86EFAC', fontFace:'Cascadia Code', bold:true,
  });

  const bullets = [
    { icon:'🔍', bold:'Scans',              rest:' 13 AWS services + Azure in a single read-only pass — no changes made to your environment' },
    { icon:'🔗', bold:'Connects the dots',  rest:' — correlates findings across services to catch broken pipelines no individual tool sees' },
    { icon:'📋', bold:'Generates a report', rest:' — self-contained HTML with prioritised findings and ready-to-run fix commands (AWS CLI)' },
    { icon:'🛡',  bold:'Security-first',    rest:' — surfaces outdated runtimes, abandoned functions with live access permissions (IAM)' },
  ];

  bullets.forEach((b, i) => {
    const y = 2.08 + i * 1.02;
    s.addText(b.icon, { x:0.5, y, w:0.5, h:0.55, fontSize:20, fontFace:'Segoe UI' });
    s.addText(
      [{ text:b.bold, options:{ bold:true, color:C.text } }, { text:b.rest, options:{ color:C.muted } }],
      { x:1.1, y:y+0.04, w:W-1.6, h:0.55, fontSize:13, fontFace:'Segoe UI' }
    );
    if (i < bullets.length - 1)
      s.addShape('rect', { x:0.45, y:y+0.68, w:W-0.9, h:0.01, fill:{ color:C.border }, line:{ color:C.border } });
  });

  footer(s);
})();

// ── SLIDE 4 — Architecture ────────────────────────────────────────────────────
(function () {
  const s = pptx.addSlide();
  bg(s);
  header(s, 'How It Works', 'Lightweight · Stateless · Read-Only');

  const bw = 3.2, bh = 3.1, by = 1.9;

  // Box 1 — Input
  box(s, 0.45, by, bw, bh, C.surf, C.blue);
  s.addShape('rect', { x:0.45, y:by, w:bw, h:0.06, fill:{ color:C.blue }, line:{ color:C.blue } });
  s.addText('YOUR CLOUD ACCOUNT', { x:0.45, y:by+0.12, w:bw, h:0.32, fontSize:9, bold:true, color:C.blue, fontFace:'Segoe UI', align:'center' });
  s.addText('Credentials + Options', { x:0.55, y:by+0.55, w:bw-0.2, h:0.35, fontSize:12, bold:true, color:C.text, fontFace:'Segoe UI', align:'center' });
  ['--provider aws | azure', '--region us-east-1', '--days 7', '--filter <team-name>'].forEach((opt, i) => {
    s.addText(opt, { x:0.55, y:by+1.02+i*0.5, w:bw-0.2, h:0.42, fontSize:10.5, color:C.muted, fontFace:'Cascadia Code', align:'center' });
  });

  // Arrow 1
  arrow(s, 3.75, by+1.48, 1.15);

  // Box 2 — CloudLens Engine (slightly taller, highlighted)
  box(s, 5.05, by-0.22, bw+0.2, bh+0.4, TINT[C.aws] || 'FFFBEB', C.aws);
  s.addShape('rect', { x:5.05, y:by-0.22, w:bw+0.2, h:0.07, fill:{ color:C.aws }, line:{ color:C.aws } });
  s.addText('CLOUDLENS ENGINE', { x:5.05, y:by-0.07, w:bw+0.2, h:0.32, fontSize:9, bold:true, color:C.aws, fontFace:'Segoe UI', align:'center' });
  s.addText('13 AWS Services', { x:5.15, y:by+0.35, w:bw, h:0.35, fontSize:12, bold:true, color:C.text, fontFace:'Segoe UI', align:'center' });
  ['Lambda  ·  EventBridge  ·  DynamoDB', 'SQS  ·  SNS  ·  S3  ·  API Gateway', 'ECS  ·  CloudFront  ·  MSK  ·  more'].forEach((svc, i) => {
    s.addText(svc, { x:5.15, y:by+0.78+i*0.47, w:bw, h:0.4, fontSize:9.5, color:C.muted, fontFace:'Segoe UI', align:'center' });
  });
  s.addText('Cross-service correlation', { x:5.15, y:by+2.12, w:bw, h:0.32, fontSize:10, bold:true, color:C.aws, fontFace:'Segoe UI', align:'center' });

  // Arrow 2
  arrow(s, 8.45, by+1.48, 1.15);

  // Box 3 — Output
  box(s, 9.7, by, bw, bh, C.surf, C.green);
  s.addShape('rect', { x:9.7, y:by, w:bw, h:0.06, fill:{ color:C.green }, line:{ color:C.green } });
  s.addText('HTML REPORT', { x:9.7, y:by+0.12, w:bw, h:0.32, fontSize:9, bold:true, color:C.green, fontFace:'Segoe UI', align:'center' });
  s.addText('Self-Contained Report', { x:9.8, y:by+0.55, w:bw-0.2, h:0.35, fontSize:12, bold:true, color:C.text, fontFace:'Segoe UI', align:'center' });
  ['Prioritised findings', 'Metrics per resource', 'Fix commands (AWS CLI)', 'Export to CSV'].forEach((item, i) => {
    s.addText(`· ${item}`, { x:9.85, y:by+1.05+i*0.5, w:bw-0.2, h:0.42, fontSize:11, color:C.muted, fontFace:'Segoe UI' });
  });

  s.addText('+ Azure: Functions · VMs · App Service · Cosmos DB · Service Bus', {
    x:0.45, y:5.15, w:W-0.9, h:0.3, fontSize:10, color:C.muted, fontFace:'Segoe UI', align:'center', italic:true,
  });

  footer(s);
})();

// ── SLIDE 5 — The Differentiator ─────────────────────────────────────────────
(function () {
  const s = pptx.addSlide();
  bg(s);
  header(s, 'The Key Differentiator', 'Cross-service correlation — what no single tool does today');

  // Left: other tools
  box(s, 0.45, 1.28, 5.9, 2.35, C.surf, C.border);
  s.addText('Every other tool (e.g. Trusted Advisor)', { x:0.6, y:1.44, w:5.6, h:0.36, fontSize:12, color:C.muted, fontFace:'Segoe UI', bold:true });
  s.addText('"A Lambda function is idle."', { x:0.6, y:1.85, w:5.6, h:0.52, fontSize:17, color:C.text, fontFace:'Segoe UI', italic:true });
  s.addText('One service at a time. No context. No correlation.', { x:0.6, y:2.42, w:5.6, h:0.38, fontSize:11, color:C.muted, fontFace:'Segoe UI' });

  s.addText('vs', { x:6.22, y:2.05, w:0.88, h:0.55, fontSize:22, color:C.border, fontFace:'Segoe UI', bold:true, align:'center' });

  // Right: CloudLens
  box(s, 7.0, 1.28, 5.88, 2.35, TINT[C.purple], C.purple);
  s.addShape('rect', { x:7.0, y:1.28, w:5.88, h:0.06, fill:{ color:C.purple }, line:{ color:C.purple } });
  s.addText('CloudLens', { x:7.18, y:1.44, w:5.5, h:0.36, fontSize:12, color:C.purple, fontFace:'Segoe UI', bold:true });
  s.addText('"The whole pipeline is broken — the schedule is running, but nothing is arriving. No alarm fired."', {
    x:7.18, y:1.85, w:5.5, h:0.72, fontSize:15, color:C.text, fontFace:'Segoe UI', italic:true,
  });
  s.addText('EventBridge (scheduler) + Lambda (target) correlated automatically.', { x:7.18, y:2.62, w:5.5, h:0.38, fontSize:11, color:C.muted, fontFace:'Segoe UI' });

  // Three pillars
  const pillars = [
    { title:'Cross-service correlation', desc:'Finds failures that span multiple services', color:C.purple },
    { title:'Security-first findings',   desc:'EOL runtimes · dead code · live IAM exposure', color:C.red   },
    { title:'Ready-to-run fix commands', desc:'Copy, paste, done — no AWS console needed', color:C.green   },
  ];
  pillars.forEach((p, i) => {
    const x = 0.45 + i * 4.28;
    card(s, x, 3.82, 4.08, 1.42, p.color);
    s.addText(p.title, { x:x+0.15, y:3.95, w:3.78, h:0.45, fontSize:14, bold:true, color:p.color, fontFace:'Segoe UI' });
    s.addText(p.desc,  { x:x+0.15, y:4.44, w:3.78, h:0.5,  fontSize:11, color:C.muted, fontFace:'Segoe UI' });
  });

  footer(s);
})();

// ── SLIDE 6 — Live Results ─────────────────────────────────────────────────────
(function () {
  const s = pptx.addSlide();
  bg(s);
  header(s, 'Live Results', 'Real scan · Test environment · 7-day window');

  const metrics = [
    { v:'117', label:'Resources Scanned', color:C.muted  },
    { v:'41',  label:'Total Findings',    color:C.blue   },
    { v:'24',  label:'HIGH Priority',     color:C.red    },
    { v:'8',   label:'MEDIUM Priority',   color:C.orange },
    { v:'9',   label:'LOW Priority',      color:C.yellow },
  ];

  metrics.forEach((m, i) => {
    const x = 0.45 + i * 2.5;
    box(s, x, 1.28, 2.35, 1.35, C.surf, C.border);
    s.addText(m.v,     { x, y:1.34, w:2.35, h:0.78, fontSize:42, bold:true, color:m.color, fontFace:'Segoe UI', align:'center' });
    s.addText(m.label, { x, y:2.1,  w:2.35, h:0.42, fontSize:9,  color:C.muted,  fontFace:'Segoe UI', align:'center' });
  });

  const findings = [
    {
      label: 'Silent Pipeline',
      color: C.orange,
      detail:'Scheduler (EventBridge rule) was active and running, but no work was arriving at its target function (Lambda). No alarm fired.',
    },
    {
      label: 'EOL Runtime',
      color: C.red,
      detail:'Functions running outdated software versions (Node.js 18 / Python 3.9) that AWS no longer patches — security holes permanently open.',
    },
    {
      label: 'Dead Code',
      color: C.red,
      detail:'Functions deployed months ago with zero use, still holding active access permissions (IAM roles). An unnecessary attack surface.',
    },
    {
      label: 'Traffic Anomaly',
      color: C.orange,
      detail:'Sharp drop in invocations vs prior period — likely a silent upstream failure that automated monitoring didn\'t catch.',
    },
  ];

  findings.forEach((f, i) => {
    const y = 2.85 + i * 0.72;
    box(s, 0.45, y, W-0.9, 0.62, C.surf, C.border);
    s.addShape('roundRect', { x:0.6, y:y+0.18, w:1.55, h:0.25, fill:{ color:f.color, transparency:84 }, line:{ color:f.color, width:0.75 }, rectRadius:0.12 });
    s.addText(f.label,  { x:0.6, y:y+0.18, w:1.55, h:0.25, fontSize:7.5, bold:true, color:f.color, fontFace:'Segoe UI', align:'center', valign:'middle' });
    s.addText(f.detail, { x:2.35, y:y+0.12, w:W-2.95, h:0.4, fontSize:9.5, color:C.muted, fontFace:'Segoe UI', valign:'middle' });
  });

  footer(s);
})();

// ── SLIDE 7 — Business Impact ─────────────────────────────────────────────────
(function () {
  const s = pptx.addSlide();
  bg(s);
  header(s, 'Business Impact', '');

  const items = [
    {
      color: C.blue,
      title: 'Platform Reliability',
      desc:  'Catch broken automated workflows before customers notice. End-to-end visibility across event-driven pipelines.',
    },
    {
      color: C.red,
      title: 'Security & Compliance',
      desc:  'Outdated runtimes create open audit findings that block certifications. Abandoned code with live permissions is unnecessary risk.',
    },
    {
      color: C.green,
      title: 'Engineering Velocity',
      desc:  'Automated cloud hygiene audit replaces hours of manual review. Fix commands bundled — no console navigation required.',
    },
    {
      color: C.purple,
      title: 'Runs Anywhere',
      desc:  'Any AWS account · Any region · Azure included · --filter to scope to a single team or service.',
    },
  ];

  items.forEach((item, i) => {
    const col = i % 2;
    const row = Math.floor(i / 2);
    const x = 0.45 + col * 6.35;
    const y = 1.35 + row * 2.68;
    card(s, x, y, 6.1, 2.45, item.color);
    s.addText(item.title, { x:x+0.18, y:y+0.18, w:5.74, h:0.45, fontSize:16, bold:true, color:item.color, fontFace:'Segoe UI' });
    s.addText(item.desc,  { x:x+0.18, y:y+0.72, w:5.74, h:1.5,  fontSize:12, color:C.muted, fontFace:'Segoe UI', wrap:true });
  });

  footer(s);
})();

// ── SLIDE 8 — What's Next ─────────────────────────────────────────────────────
(function () {
  const s = pptx.addSlide();
  bg(s);
  header(s, "What's Next", 'Built at the hackathon — production-ready with these additions');

  const items = [
    { color:C.green,  title:'GitHub Actions',          desc:'Weekly automated scan. HTML report committed to the repo. Git history becomes your trend data — no extra tooling.' },
    { color:C.blue,   title:'Email Digest',             desc:'Findings summary emailed to engineering leads after each run. No dashboard to log in to.' },
    { color:C.aws,    title:'Multi-Account Scanning',   desc:'One command scans every account in an AWS Organisation. Full estate visibility at once.' },
    { color:C.purple, title:'Auto-Remediation',         desc:'--auto-fix flag applies safe, pre-approved fixes directly: log retention, tag enforcement, runtime upgrades.' },
  ];

  items.forEach((item, i) => {
    const y = 1.32 + i * 1.43;
    card(s, 0.45, y, W-0.9, 1.23, item.color);
    s.addText(item.title, { x:0.68, y:y+0.15, w:3.5,    h:0.42, fontSize:15, bold:true, color:item.color, fontFace:'Segoe UI' });
    s.addText(item.desc,  { x:0.68, y:y+0.62, w:W-1.35, h:0.5,  fontSize:11, color:C.muted, fontFace:'Segoe UI' });
  });

  footer(s);
})();

// ── SLIDE 9 — Close ───────────────────────────────────────────────────────────
(function () {
  const s = pptx.addSlide();
  bg(s);

  // Top navy band
  s.addShape('rect', { x:0, y:0, w:W, h:2.0, fill:{ color:C.header }, line:{ color:C.header } });
  s.addShape('rect', { x:0, y:0, w:0.12, h:2.0, fill:{ color:C.aws }, line:{ color:C.aws } });
  s.addText(
    [{ text:'Cloud', options:{ color:C.white, bold:true } },
     { text:'Lens',  options:{ color:'93C5FD', bold:true } }],
    { x:0.38, y:0.2, w:8, h:1.0, fontSize:38, fontFace:'Segoe UI' }
  );
  s.addText('Working MVP  ·  Live AWS + Azure  ·  Demo-ready today', {
    x:0.38, y:1.15, w:W-0.76, h:0.45, fontSize:13, color:'93C5FD', fontFace:'Segoe UI',
  });

  const checks = [
    { text:'13 AWS services + Azure — one read-only command, zero risk to production',        color:C.green  },
    { text:'Cross-service pipeline correlation — not available in any other tool',             color:C.purple },
    { text:'Security findings: outdated runtimes, abandoned code with live permissions (IAM)', color:C.red    },
    { text:'Ready-to-run fix commands bundled in every report — no AWS console needed',        color:C.blue   },
  ];

  checks.forEach((c, i) => {
    dot(s, 0.48, 2.38+i*0.72+0.04, c.color);
    s.addText(c.text, { x:0.74, y:2.35+i*0.72, w:W-1.1, h:0.5, fontSize:13, color:C.text, fontFace:'Segoe UI' });
  });

  box(s, 0.45, 5.42, W-0.9, 0.88, TINT[C.purple], C.purple);
  s.addShape('rect', { x:0.45, y:5.42, w:W-0.9, h:0.06, fill:{ color:C.purple }, line:{ color:C.purple } });
  s.addText(
    '"The gap between \'alert didn\'t fire\' and \'customer reported it\' — that\'s where CloudLens operates."',
    { x:0.62, y:5.52, w:W-1.22, h:0.65, fontSize:14, color:C.text, fontFace:'Segoe UI', italic:true, align:'center', valign:'middle' }
  );

  footer(s);
})();

// ── Write ─────────────────────────────────────────────────────────────────────
pptx.writeFile({ fileName: 'cloudlens-presentation.pptx' })
  .then(() => console.log('cloudlens-presentation.pptx written'))
  .catch(err => { console.error(err.message); process.exit(1); });
