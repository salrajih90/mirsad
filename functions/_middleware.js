/* بوابة كلمة مرور للمرصد المالي والاقتصادي — Cloudflare Pages Function.
 *
 * نسخة مطابقة لبوابة لوحة تاسي، منقولة إلى هذا المستودع لأن كل مشروع نشر يحمل
 * وسيطه الخاص. الحماية على مستوى الحافة: تعترض كل طلب قبل الوصول إلى الأصول، فلا
 * يُخدم ملف بيانات ولا سكربت دون كلمة المرور — لا الواجهة وحدها.
 *
 * الإعداد (من لوحة Cloudflare ← المشروع almirsad ← Settings ← Variables and secrets):
 *   DASH_PASSWORD  — كلمة المرور المشتركة.            (Secret)
 *   AUTH_SECRET    — سلسلة عشوائية طويلة لتوقيع الجلسة. (Secret)
 *
 * إن لم تُضبط DASH_PASSWORD تمر الطلبات بلا حماية — حتى لا يُقفل الموقع على صاحبه
 * قبل إتمام الإعداد. */

const COOKIE = 'mrsd_auth';
const DAYS = 30;

const enc = new TextEncoder();

async function sign(secret, msg) {
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(msg));
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, '0')).join('');
}

/* مقارنة ثابتة الزمن: المقارنة العادية تُنهي عند أول اختلاف، فيتسرب طول البادئة
   الصحيحة عبر زمن الاستجابة. */
function eq(a, b) {
  const x = enc.encode(String(a)), y = enc.encode(String(b));
  let d = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) d |= (x[i] || 0) ^ (y[i] || 0);
  return d === 0;
}

async function valid(cookieHeader, secret) {
  const m = /(?:^|;\s*)mrsd_auth=([^;]+)/.exec(cookieHeader || '');
  if (!m) return false;
  const [expStr, sig] = decodeURIComponent(m[1]).split('.');
  const exp = Number(expStr);
  if (!exp || Date.now() > exp) return false;
  return eq(sig, await sign(secret, expStr));
}

function page(err) {
  return `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>المرصد المالي والاقتصادي — دخول</title><style>
:root{--bg:#0d1117;--surface:#161b22;--line:#30363d;--txt:#e6edf3;--dim:#8b949e;--brand:#c8a86b}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:var(--bg);color:var(--txt);
font:15px/1.7 -apple-system,"Segoe UI",system-ui,sans-serif;padding:24px}
.box{width:100%;max-width:380px;background:var(--surface);border:1px solid var(--line);
border-radius:14px;padding:32px 28px}
h1{margin:0 0 6px;font-size:19px;font-weight:650}
p{margin:0 0 22px;color:var(--dim);font-size:13px}
label{display:block;font-size:12px;color:var(--dim);margin-bottom:6px}
input{width:100%;padding:11px 13px;border-radius:9px;border:1px solid var(--line);
background:var(--bg);color:var(--txt);font-size:15px;font-family:inherit}
input:focus{outline:none;border-color:var(--brand)}
button{width:100%;margin-top:16px;padding:11px;border:0;border-radius:9px;background:var(--brand);
color:#0d1117;font-weight:650;font-size:15px;font-family:inherit;cursor:pointer}
button:hover{filter:brightness(1.08)}
.err{margin-top:14px;padding:9px 12px;border-radius:8px;background:#2d1618;border:1px solid #6e2b31;
color:#ffb4ab;font-size:13px}
.ft{margin-top:20px;font-size:11px;color:var(--dim);line-height:1.6}
</style></head><body><form class="box" method="POST">
<h1>المرصد المالي والاقتصادي</h1>
<p>مؤشرات الاقتصاد الكلي والأسواق والمالية العامة — الوصول محمي.</p>
<label for="p">كلمة المرور</label>
<input id="p" name="p" type="password" autocomplete="current-password" autofocus required>
<button type="submit">دخول</button>
${err ? '<div class="err">كلمة المرور غير صحيحة.</div>' : ''}
<div class="ft">تبقى الجلسة مفتوحة ${DAYS} يوماً على هذا المتصفح.</div>
</form></body></html>`;
}



export async function onRequest(context) {
  const { request, env, next } = context;
  const pw = env.DASH_PASSWORD;
  if (!pw) return next();                       // لم تُضبط الحماية بعد — لا تُقفل اللوحة
  const secret = env.AUTH_SECRET || pw;

  if (await valid(request.headers.get('Cookie'), secret)) return next();

  if (request.method === 'POST') {
    let given = '';
    try {
      const form = await request.formData();
      given = form.get('p') || '';
    } catch (e) { /* جسم غير صالح — يُعامل ككلمة خاطئة */ }
    if (eq(given, pw)) {
      const exp = Date.now() + DAYS * 864e5;
      const val = encodeURIComponent(`${exp}.${await sign(secret, String(exp))}`);
      return new Response(null, {
        status: 303,
        headers: {
          'Location': new URL(request.url).pathname,
          'Set-Cookie': `${COOKIE}=${val}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${DAYS * 86400}`,
          'Cache-Control': 'no-store',
        },
      });
    }
    await new Promise(r => setTimeout(r, 600));   // إبطاء محاولات التخمين المتتابعة
    return new Response(page(true), {
      status: 401,
      headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
    });
  }

  return new Response(page(false), {
    status: 401,
    headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' },
  });
}
