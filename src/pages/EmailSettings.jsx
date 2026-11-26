// Settings -> Email: how invitation emails are delivered (off / test outbox / real SMTP).
// The SMTP password is write-only: the server never sends it back.
import { useCallback, useEffect, useState } from 'react';
import { Mail, Send, Save, Loader2, Inbox, Trash2, FlaskConical, PowerOff, Server, CheckCircle2, Lock, RefreshCw } from 'lucide-react';
import { api } from '../api.js';
import { useAuth } from '../context/AuthContext.jsx';
import { Field, Empty, Badge } from '../components/UI.jsx';
import { FormError } from './Login.jsx';
import { fmtDateTime } from '../context/StoreContext.jsx';

const MODES = [
  { key: 'off', label: 'Off', icon: PowerOff, desc: 'No emails. Copy invitation links and codes by hand.' },
  { key: 'test', label: 'Test mode', icon: FlaskConical, desc: 'Nothing is sent. Emails are saved and shown below so you can check them.' },
  { key: 'smtp', label: 'Send real email', icon: Server, desc: 'Deliver through Gmail, Outlook or any SMTP mail server.' },
];

const PRESETS = [
  { label: 'Gmail', host: 'smtp.gmail.com', port: 587, security: 'starttls', hint: 'Use a Google App Password (Google Account → Security → 2-Step Verification → App passwords), not your normal password.' },
  { label: 'Outlook / Microsoft 365', host: 'smtp.office365.com', port: 587, security: 'starttls', hint: 'Your administrator may need to allow "SMTP AUTH" for this mailbox.' },
  { label: 'Zoho', host: 'smtp.zoho.com', port: 465, security: 'ssl', hint: 'Use an app-specific password if two-factor sign-in is on.' },
];

const EMPTY = { mode: 'off', host: '', port: 587, security: 'starttls', user: '', from: '', passwordSet: false, source: 'app' };

export default function EmailSettings() {
  const { user, refresh } = useAuth();
  const [saved, setSaved] = useState(null); // what the server has
  const [form, setForm] = useState(EMPTY);
  const [password, setPassword] = useState('');
  const [hint, setHint] = useState('');
  const [busy, setBusy] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [testTo, setTestTo] = useState(user?.email || '');

  const load = useCallback(async () => {
    try {
      const { mail } = await api('/mail-settings');
      setSaved(mail);
      setForm(mail);
    } catch (err) {
      setError(err.message);
    }
  }, []);
  useEffect(() => { load(); }, [load]);

  const set = (k, v) => setForm((f) => ({ ...f, [k]: v }));
  const fromEnv = saved?.source === 'env';
  const dirty = saved && (password || ['mode', 'host', 'port', 'security', 'user', 'from'].some((k) => String(form[k]) !== String(saved[k])));

  const save = async (e) => {
    e?.preventDefault();
    setBusy('save');
    setError('');
    setNotice('');
    try {
      const body = { mode: form.mode };
      if (form.mode === 'smtp') Object.assign(body, { host: form.host.trim(), port: Number(form.port), security: form.security, user: form.user.trim(), from: form.from.trim() });
      if (password) body.password = password;
      const { mail } = await api('/mail-settings', { method: 'PUT', body });
      setSaved(mail);
      setForm(mail);
      setPassword('');
      setNotice('Email settings saved.');
      refresh?.(); // the invitation screen reads whether email is on
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  };

  const sendTest = async () => {
    setBusy('test');
    setError('');
    setNotice('');
    try {
      const r = await api('/mail-settings/test', { method: 'POST', body: { to: testTo.trim() } });
      setNotice(r.message);
    } catch (err) {
      setError(err.message);
    } finally {
      setBusy('');
    }
  };

  if (!saved && !error) return <Empty icon={Loader2}>Loading…</Empty>;

  return (
    <>
      <h2>Email</h2>
      <p className="muted small" style={{ marginTop: -6 }}>How exam invitations reach candidates. Each email contains the candidate's personal Test ID and exam link.</p>

      {fromEnv && (
        <div className="info-box small"><Lock size={16} /> Email is configured in the server's <code>.env</code> file (SMTP_HOST={saved.host}). Change it there, or remove those lines to manage email here.</div>
      )}

      <div className="mode-picker" role="radiogroup" aria-label="Email mode">
        {MODES.map((m) => (
          <button
            key={m.key}
            type="button"
            role="radio"
            aria-checked={form.mode === m.key}
            className={`mode-option ${form.mode === m.key ? 'active' : ''}`}
            disabled={fromEnv}
            onClick={() => set('mode', m.key)}
          >
            <m.icon size={18} />
            <span><b>{m.label}</b><small>{m.desc}</small></span>
          </button>
        ))}
      </div>

      {form.mode === 'smtp' && (
        <fieldset className="plain-fieldset" disabled={fromEnv}>
          <div className="preset-row">
            <span className="muted small">Quick setup:</span>
            {PRESETS.map((p) => (
              <button key={p.label} type="button" className="chip" onClick={() => { setForm((f) => ({ ...f, host: p.host, port: p.port, security: p.security })); setHint(p.hint); }}>
                {p.label}
              </button>
            ))}
          </div>
          {hint && <div className="info-box small">{hint}</div>}
          <div className="two-col">
            <Field label="SMTP server"><input id="smtp-host" className="input" placeholder="smtp.gmail.com" value={form.host} onChange={(e) => set('host', e.target.value)} required /></Field>
            <Field label="Port"><input id="smtp-port" className="input" type="number" min="1" max="65535" value={form.port} onChange={(e) => set('port', e.target.value)} required /></Field>
            <Field label="Security">
              <select id="smtp-security" className="input" value={form.security} onChange={(e) => set('security', e.target.value)}>
                <option value="starttls">STARTTLS (usually port 587)</option>
                <option value="ssl">SSL/TLS (usually port 465)</option>
                <option value="none">None (local relay only, not secure)</option>
              </select>
            </Field>
          </div>
          <div className="two-col">
            <Field label="Username"><input id="smtp-user" className="input" autoComplete="off" placeholder="you@gmail.com" value={form.user} onChange={(e) => set('user', e.target.value)} /></Field>
            <Field label={saved.passwordSet ? 'Password (saved, type to replace)' : 'Password'}>
              <input id="smtp-password" className="input" type="password" autoComplete="new-password" placeholder={saved.passwordSet ? '••••••••' : 'App password'} value={password} onChange={(e) => setPassword(e.target.value)} />
            </Field>
          </div>
          <Field label="From address (what candidates see)">
            <input id="smtp-from" className="input" placeholder="Exams <you@gmail.com>" value={form.from} onChange={(e) => set('from', e.target.value)} required />
          </Field>
        </fieldset>
      )}

      <FormError>{error}</FormError>
      {notice && <div className="form-ok" role="status"><CheckCircle2 size={15} /> {notice}</div>}

      <div className="modal-actions" style={{ justifyContent: 'space-between', flexWrap: 'wrap' }}>
        <div className="row-actions">
          {saved.mode !== 'off' && !dirty && (
            <>
              <input className="input" style={{ width: 230 }} type="email" aria-label="Send test email to" value={testTo} onChange={(e) => setTestTo(e.target.value)} />
              <button type="button" className="btn" disabled={busy === 'test'} onClick={sendTest}>
                {busy === 'test' ? <Loader2 size={14} className="spin" /> : <Send size={14} />} Send test email
              </button>
            </>
          )}
          {dirty && <span className="muted small">Save to try these settings.</span>}
        </div>
        {!fromEnv && (
          <button type="button" className="btn primary" disabled={!dirty || busy === 'save'} onClick={save}>
            {busy === 'save' ? <Loader2 size={15} className="spin" /> : <Save size={15} />} Save email settings
          </button>
        )}
      </div>

      {saved.mode === 'test' && <Outbox key={notice} />}
    </>
  );
}

function Outbox() {
  const [emails, setEmails] = useState(null);
  const [open, setOpen] = useState(null);
  const [error, setError] = useState('');
  const load = useCallback(() => {
    api('/outbox').then((r) => setEmails(r.emails), (err) => setError(err.message));
  }, []);
  useEffect(() => { load(); }, [load]);

  return (
    <div className="outbox">
      <div className="card-head" style={{ marginBottom: 8 }}>
        <div>
          <h3 style={{ margin: 0, display: 'flex', alignItems: 'center', gap: 8 }}><Inbox size={17} /> Test outbox</h3>
          <div className="card-sub">Emails Oversee would have sent. Newest first, last 50.</div>
        </div>
        <div className="row-actions">
          <button type="button" className="btn small" onClick={load}><RefreshCw size={13} /> Refresh</button>
          {emails?.length > 0 && (
            <button type="button" className="btn small danger-ghost" onClick={() => api('/outbox', { method: 'DELETE' }).then(load)}><Trash2 size={13} /> Clear</button>
          )}
        </div>
      </div>
      <FormError>{error}</FormError>
      {!emails ? (
        <Empty icon={Loader2}>Loading…</Empty>
      ) : !emails.length ? (
        <Empty icon={Mail}>No emails yet. Use "Send test email", or invite candidates from an exam with "Create and email".</Empty>
      ) : (
        <div className="outbox-list">
          {emails.map((e) => (
            <div key={e.id} className={`outbox-item ${open === e.id ? 'open' : ''}`}>
              <button type="button" className="outbox-row" onClick={() => setOpen(open === e.id ? null : e.id)} aria-expanded={open === e.id}>
                <Badge tone="purple" plain>To</Badge>
                <span className="ellipsis"><b>{e.to}</b> · {e.subject}</span>
                <span className="muted small nowrap">{fmtDateTime(e.at)}</span>
              </button>
              {open === e.id && <pre className="outbox-body">{`From: ${e.from}\nTo: ${e.to}\nSubject: ${e.subject}\n\n${e.text}`}</pre>}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
