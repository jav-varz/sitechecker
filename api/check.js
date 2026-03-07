// api/check.js — Vercel Serverless Function
// Consulta Google Web Risk + IPQualityScore y devuelve un resultado unificado

export default async function handler(req, res) {
  // Solo aceptamos POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({ error: 'URL inválida o faltante' });
  }

  // Limpiamos y validamos la URL
  let cleanUrl;
  try {
    cleanUrl = new URL(url.startsWith('http') ? url : 'https://' + url);
  } catch {
    return res.status(400).json({ error: 'No es una URL válida' });
  }

  const domain = cleanUrl.hostname.replace(/^www\./, '');
  const fullUrl = cleanUrl.href;

  // Leemos las API keys desde variables de entorno (configuradas en Vercel)
  const WEB_RISK_KEY = process.env.GOOGLE_WEB_RISK_KEY;
  const IPQS_KEY     = process.env.IPQUALITYSCORE_KEY;

  // Ejecutamos ambas consultas en paralelo para mayor velocidad
  const [webRiskResult, ipqsResult] = await Promise.allSettled([
    checkWebRisk(fullUrl, WEB_RISK_KEY),
    checkIPQS(fullUrl, IPQS_KEY),
  ]);

  const webRisk = webRiskResult.status === 'fulfilled' ? webRiskResult.value : null;
  const ipqs    = ipqsResult.status    === 'fulfilled' ? ipqsResult.value    : null;

  // ── Construimos el resultado unificado ──────────────────────────────────────
  const checks = buildChecks(webRisk, ipqs, cleanUrl);
  const verdict = calcVerdict(checks);
  const message = VERDICT_MESSAGES[verdict];

  return res.status(200).json({
    domain,
    verdict,      // 'green' | 'yellow' | 'red' | 'gray'
    title:   message.title,
    desc:    message.desc,
    checks,
    attribution: {
      webRisk: 'Advisory provided by Google (Web Risk)',
      ipqs:    'URL analysis by IPQualityScore',
    },
  });
}

// ── Google Web Risk ──────────────────────────────────────────────────────────
async function checkWebRisk(url, apiKey) {
  if (!apiKey) return { available: false };

  const encoded  = encodeURIComponent(url);
  const endpoint = `https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&threatTypes=UNWANTED_SOFTWARE&uri=${encoded}&key=${apiKey}`;

  const response = await fetch(endpoint, { signal: AbortSignal.timeout(5000) });
  if (!response.ok) return { available: false };

  const data = await response.json();

  // Si viene "threat" en la respuesta, el sitio está en la lista negra
  const isFlagged = !!(data.threat);
  const threatType = isFlagged ? data.threat?.threatTypes?.[0] ?? 'UNKNOWN' : null;

  return { available: true, isFlagged, threatType };
}

// ── IPQualityScore ───────────────────────────────────────────────────────────
async function checkIPQS(url, apiKey) {
  if (!apiKey) return { available: false };

  const encoded  = encodeURIComponent(url);
  const endpoint = `https://www.ipqualityscore.com/api/json/url/${apiKey}/${encoded}?strictness=1&fast=1`;

  const response = await fetch(endpoint, { signal: AbortSignal.timeout(5000) });
  if (!response.ok) return { available: false };

  const data = await response.json();

  return {
    available:    true,
    phishing:     data.phishing     ?? false,
    malware:      data.malware      ?? false,
    suspicious:   data.suspicious   ?? false,
    spam:         data.spamming     ?? false,
    riskScore:    data.risk_score   ?? 0,     // 0–100, mayor = más riesgo
    domainAge:    data.domain_age?.human ?? 'Desconocida',
    hasHttps:     (data.server ?? '').includes('443') || url.startsWith('https'),
    category:     data.category     ?? null,
  };
}

// ── Construir lista de checks para mostrar en el frontend ────────────────────
function buildChecks(webRisk, ipqs, parsedUrl) {
  const checks = [];

  // Check 1: Google Web Risk
  if (webRisk?.available) {
    checks.push({
      icon:  '🛡️',
      label: 'Google Web Risk',
      value: webRisk.isFlagged ? 'Detectado' : 'Limpio',
      cls:   webRisk.isFlagged ? 'danger' : 'ok',
    });
  } else {
    checks.push({ icon: '🛡️', label: 'Google Web Risk', value: 'No disponible', cls: 'na' });
  }

  // Check 2: Phishing / Malware (IPQS)
  if (ipqs?.available) {
    const isBad = ipqs.phishing || ipqs.malware;
    checks.push({
      icon:  '🦠',
      label: 'Phishing / Malware',
      value: isBad ? 'Detectado' : 'Limpio',
      cls:   isBad ? 'danger' : 'ok',
    });

    // Check 3: Risk Score
    const riskCls = ipqs.riskScore >= 75 ? 'danger' : ipqs.riskScore >= 40 ? 'warn' : 'ok';
    checks.push({
      icon:  '📊',
      label: 'Puntuación de riesgo',
      value: `${ipqs.riskScore} / 100`,
      cls:   riskCls,
    });

    // Check 4: Antigüedad del dominio
    checks.push({
      icon:  '📅',
      label: 'Antigüedad',
      value: ipqs.domainAge,
      cls:   ipqs.domainAge === 'Desconocida' ? 'na' : 'ok',
    });
  } else {
    checks.push({ icon: '🦠', label: 'Phishing / Malware', value: 'No disponible', cls: 'na' });
    checks.push({ icon: '📊', label: 'Puntuación de riesgo', value: '—', cls: 'na' });
    checks.push({ icon: '📅', label: 'Antigüedad', value: '—', cls: 'na' });
  }

  // Check 5: HTTPS
  const hasHttps = parsedUrl.protocol === 'https:';
  checks.push({
    icon:  '🔒',
    label: 'HTTPS',
    value: hasHttps ? 'Sí' : 'No',
    cls:   hasHttps ? 'ok' : 'warn',
  });

  return checks;
}

// ── Calcular veredicto final ─────────────────────────────────────────────────
function calcVerdict(checks) {
  // Si alguna fuente principal detecta amenaza → ROJO
  const hasDanger = checks.some(c => c.cls === 'danger');
  if (hasDanger) return 'red';

  // Si ninguna fuente está disponible → GRIS
  const allNA = checks.every(c => c.cls === 'na');
  if (allNA) return 'gray';

  // Si hay advertencias → AMARILLO
  const hasWarn = checks.some(c => c.cls === 'warn');
  if (hasWarn) return 'yellow';

  // Todo limpio → VERDE
  return 'green';
}

// ── Mensajes por veredicto ───────────────────────────────────────────────────
const VERDICT_MESSAGES = {
  green: {
    title: 'Sitio Confiable',
    desc:  'Este sitio no presenta señales de riesgo. Fue verificado como seguro por Google Web Risk e IPQualityScore. Aun así, verifica siempre que la URL sea exactamente la correcta.',
  },
  yellow: {
    title: 'Precaución',
    desc:  'Este sitio tiene algunas características que merecen atención. Puede ser legítimo, pero te recomendamos no ingresar información sensible si tienes dudas.',
  },
  red: {
    title: 'Sitio Peligroso',
    desc:  'Este sitio fue marcado como malicioso o sospechoso por nuestras fuentes de seguridad. No recomendamos acceder ni ingresar ningún dato personal o financiero.',
  },
  gray: {
    title: 'Sin Información',
    desc:  'No encontramos información suficiente para evaluar este sitio. Puede ser muy nuevo o estar fuera del alcance de las bases de datos consultadas. Procede con cautela.',
  },
};
