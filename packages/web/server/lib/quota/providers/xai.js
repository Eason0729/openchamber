import { readAuthFile } from '../../opencode/auth.js';
import {
  getAuthEntry,
  normalizeAuthEntry,
  buildResult,
  toUsageWindow,
  toTimestamp
} from '../utils/index.js';

export const providerId = 'xai';
export const providerName = 'xAI (Grok)';
const aliases = ['xai'];

const USERINFO_URL = 'https://auth.x.ai/oauth2/userinfo';
const BILLING_URL = 'https://cli-chat-proxy.grok.com/v1/billing?format=credits';

const isOAuthEntry = (entry) => {
  if (!entry) return false;
  if (entry.type && entry.type !== 'oauth') return false;
  return Boolean(entry.access);
};

export const isConfigured = () => {
  const auth = readAuthFile();
  const entry = normalizeAuthEntry(getAuthEntry(auth, aliases));
  return isOAuthEntry(entry);
};

const fetchUserId = async (accessToken, signal) => {
  const response = await fetch(USERINFO_URL, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json'
    },
    signal
  });
  if (!response.ok) {
    throw new Error(`xAI userinfo error: ${response.status}`);
  }
  const payload = await response.json();
  const sub = payload?.sub;
  if (typeof sub !== 'string' || !sub) {
    throw new Error('xAI userinfo response missing sub');
  }
  return sub;
};

const resolveWindowKey = (periodType) => {
  if (typeof periodType === 'string' && periodType.includes('WEEKLY')) return 'weekly';
  if (typeof periodType === 'string' && periodType.includes('MONTHLY')) return 'monthly';
  return 'credits';
};

export const fetchQuota = async () => {
  const auth = readAuthFile();
  const entry = normalizeAuthEntry(getAuthEntry(auth, aliases));

  if (!isOAuthEntry(entry)) {
    return buildResult({
      providerId,
      providerName,
      ok: false,
      configured: false,
      error: 'Not configured'
    });
  }

  const accessToken = entry.access;
  const timeoutSignal = AbortSignal.timeout(15_000);

  try {
    const userId = await fetchUserId(accessToken, timeoutSignal);

    const response = await fetch(BILLING_URL, {
      method: 'GET',
      headers: {
        Authorization: `Bearer ${accessToken}`,
        'x-userid': userId,
        'X-XAI-Token-Auth': 'xai-grok-cli',
        'x-grok-client-mode': 'interactive',
        Accept: 'application/json'
      },
      signal: timeoutSignal
    });

    if (!response.ok) {
      return buildResult({
        providerId,
        providerName,
        ok: false,
        configured: true,
        error: `API error: ${response.status}`
      });
    }

    const payload = await response.json();
    const config = payload?.config ?? {};

    const creditUsagePercent = typeof config.creditUsagePercent === 'number'
      ? config.creditUsagePercent
      : null;
    const limit = config.monthlyLimit?.val ?? null;
    const used = config.used?.val ?? null;

    let usedPercent = creditUsagePercent;
    if (usedPercent === null && limit !== null && used !== null && limit > 0) {
      usedPercent = Math.min(100, (used / limit) * 100);
    }

    const period = config.currentPeriod ?? {};
    const periodType = period.type ?? null;
    const resetAt = toTimestamp(period.end) ?? toTimestamp(config.billingPeriodEnd) ?? null;

    const onDemandCap = config.onDemandCap?.val ?? null;
    const onDemandUsed = config.onDemandUsed?.val ?? null;
    const prepaidBalance = config.prepaidBalance?.val ?? null;

    const windowKey = resolveWindowKey(periodType);

    const labelParts = [];
    if (typeof usedPercent === 'number') {
      labelParts.push(`${Math.floor(usedPercent)}%`);
    }
    if (onDemandCap !== null && onDemandCap > 0 && onDemandUsed !== null) {
      const onDemandPct = Math.min(100, (onDemandUsed / onDemandCap) * 100);
      labelParts.push(`on-demand ${Math.floor(onDemandPct)}%`);
    }
    if (prepaidBalance !== null && prepaidBalance !== 0) {
      const prepaidUsd = (prepaidBalance / 100).toFixed(2);
      labelParts.push(`$${prepaidUsd} prepaid`);
    }
    const valueLabel = labelParts.length > 0 ? labelParts.join(' · ') : null;

    const windows = {
      [windowKey]: toUsageWindow({
        usedPercent,
        windowSeconds: null,
        resetAt,
        valueLabel
      })
    };

    return buildResult({
      providerId,
      providerName,
      ok: true,
      configured: true,
      usage: { windows }
    });
  } catch (error) {
    const isTimeout = error instanceof DOMException && error.name === 'AbortError' && timeoutSignal.aborted;
    const isParseError = error instanceof SyntaxError;
    return buildResult({
      providerId,
      providerName,
      ok: false,
      configured: true,
      error: isTimeout
        ? 'Request timed out'
        : isParseError
          ? 'Invalid response from provider'
          : (error instanceof Error ? error.message : 'Request failed')
    });
  }
};