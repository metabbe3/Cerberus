import { createHash } from "node:crypto";

export class CerberusError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CerberusError";
    Object.setPrototypeOf(this, CerberusError.prototype);
  }
}

export class ErrDenied extends CerberusError {
  readonly rule_id: string;
  readonly reason: string;

  constructor(ruleId: string, reason: string) {
    super(`cerberus: tool execution denied by rule "${ruleId}": ${reason}`);
    this.name = "ErrDenied";
    this.rule_id = ruleId;
    this.reason = reason;
    Object.setPrototypeOf(this, ErrDenied.prototype);
  }
}

export interface DecisionData {
  decision: string;
  rule_id?: string;
  reason?: string;
  masked_args?: Record<string, any>;
  epoch?: number;
  cached?: boolean;
}

export class Decision {
  readonly decision: string;
  readonly rule_id: string;
  readonly reason: string;
  readonly masked_args?: Record<string, any>;
  readonly epoch?: number;
  readonly cached: boolean;

  constructor(data: DecisionData) {
    this.decision = data.decision;
    this.rule_id = data.rule_id || "";
    this.reason = data.reason || "";
    this.masked_args = data.masked_args;
    this.epoch = data.epoch;
    this.cached = !!data.cached;
  }

  allowed(): boolean {
    return this.decision === "allow";
  }

  get isAllowed(): boolean {
    return this.allowed();
  }

  toJSON(): DecisionData {
    return {
      decision: this.decision,
      rule_id: this.rule_id,
      reason: this.reason,
      masked_args: this.masked_args,
      epoch: this.epoch,
      cached: this.cached,
    };
  }
}

export interface ClientOptions {
  baseUrl?: string;
  keyId?: string;
  maxRetries?: number;
  retryDelayMs?: number;
  cacheTtlMs?: number;
  disableCache?: boolean;
  timeoutMs?: number;
}

export interface MetricsSnapshot {
  totalCalls: number;
  allowedCalls: number;
  deniedCalls: number;
  cacheHits: number;
  cacheMisses: number;
  retries: number;
  errors: number;
}

interface CachedVerdict {
  decision: Decision;
  expiresAt: number;
}

function canonicalJson(obj: any): string {
  if (obj === null || typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalJson).join(",") + "]";
  }
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJson(obj[k])).join(",") + "}";
}

function hashToolCall(tool: string, args: Record<string, any>): string {
  const c = canonicalJson(args);
  const hash = createHash("sha256");
  hash.update(tool);
  hash.update("\0");
  hash.update(c);
  return hash.digest("hex");
}

export class CerberusClient {
  readonly baseUrl: string;
  readonly keyId: string;
  readonly maxRetries: number;
  readonly retryDelayMs: number;
  readonly cacheTtlMs: number;
  readonly disableCache: boolean;
  readonly timeoutMs: number;

  private cache = new Map<string, CachedVerdict>();

  private _totalCalls = 0;
  private _allowedCalls = 0;
  private _deniedCalls = 0;
  private _cacheHits = 0;
  private _cacheMisses = 0;
  private _retries = 0;
  private _errors = 0;

  constructor(options: ClientOptions = {}) {
    this.baseUrl = (options.baseUrl || "http://127.0.0.1:8089").replace(/\/+$/, "");
    this.keyId = options.keyId || "";
    this.maxRetries = options.maxRetries !== undefined ? Math.max(0, options.maxRetries) : 1;
    this.retryDelayMs = options.retryDelayMs !== undefined ? Math.max(0, options.retryDelayMs) : 50;
    this.cacheTtlMs = options.cacheTtlMs !== undefined ? Math.max(0, options.cacheTtlMs) : 60000;
    this.disableCache = !!options.disableCache;
    this.timeoutMs = options.timeoutMs !== undefined ? options.timeoutMs : 5000;
  }

  metrics(): MetricsSnapshot {
    return {
      totalCalls: this._totalCalls,
      allowedCalls: this._allowedCalls,
      deniedCalls: this._deniedCalls,
      cacheHits: this._cacheHits,
      cacheMisses: this._cacheMisses,
      retries: this._retries,
      errors: this._errors,
    };
  }

  private normalizeArgs(args: any): Record<string, any> {
    if (args === null || args === undefined) {
      return {};
    }
    if (typeof args === "object" && !Array.isArray(args)) {
      return args;
    }
    try {
      return JSON.parse(JSON.stringify(args));
    } catch (e: any) {
      throw new CerberusError(`cerberus: normalize args: ${e.message}`);
    }
  }

  async decideTool(tool: string, args: any = {}): Promise<Decision> {
    this._totalCalls++;

    const argsMap = this.normalizeArgs(args);
    const key = hashToolCall(tool, argsMap);
    const now = Date.now();

    if (!this.disableCache) {
      const cached = this.cache.get(key);
      if (cached) {
        if (now < cached.expiresAt) {
          this._cacheHits++;
          const d = new Decision({
            ...cached.decision.toJSON(),
            cached: true,
          });
          if (d.allowed()) {
            this._allowedCalls++;
          } else {
            this._deniedCalls++;
          }
          return d;
        } else {
          this.cache.delete(key);
        }
      }
    }

    this._cacheMisses++;

    const reqBody = {
      stage: "tool",
      key_id: this.keyId,
      tool_call: tool,
      args: argsMap,
    };

    let dec: Decision;
    try {
      dec = await this.doWithRetry(reqBody);
    } catch (err) {
      this._errors++;
      throw err;
    }

    if (dec.allowed()) {
      this._allowedCalls++;
    } else {
      this._deniedCalls++;
    }

    if (!this.disableCache && !dec.rule_id.startsWith("internal.")) {
      this.cache.set(key, {
        decision: dec,
        expiresAt: Date.now() + this.cacheTtlMs,
      });
    }

    return dec;
  }

  private async doWithRetry(body: Record<string, any>): Promise<Decision> {
    const url = `${this.baseUrl}/v1/decide`;
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
    };
    if (this.keyId) {
      headers["X-Cerberus-Key"] = this.keyId;
    }

    const jsonString = JSON.stringify(body);
    let delay = this.retryDelayMs;
    let lastErr: Error | null = null;
    const totalAttempts = 1 + this.maxRetries;

    for (let attempt = 0; attempt < totalAttempts; attempt++) {
      if (attempt > 0) {
        this._retries++;
        await new Promise((res) => setTimeout(res, delay));
        delay *= 2;
      }

      let resp: Response;
      try {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), this.timeoutMs);
        resp = await fetch(url, {
          method: "POST",
          headers,
          body: jsonString,
          signal: controller.signal,
        });
        clearTimeout(timer);
      } catch (err: any) {
        lastErr = err;
        continue;
      }

      if (resp.status >= 500) {
        lastErr = new CerberusError(`server error status ${resp.status}`);
        continue;
      }

      const text = await resp.text();
      if (!resp.ok) {
        throw new CerberusError(`unexpected status ${resp.status}: ${text}`);
      }

      let parsed: any;
      try {
        parsed = JSON.parse(text);
      } catch (err: any) {
        throw new CerberusError(`unmarshal decision: ${err.message}`);
      }

      return new Decision({
        decision: parsed.decision ?? "deny",
        rule_id: parsed.rule_id ?? "",
        reason: parsed.reason ?? "",
        masked_args: parsed.masked_args,
        epoch: parsed.epoch,
        cached: false,
      });
    }

    throw new CerberusError(
      `cerberus: request failed after ${totalAttempts} attempts: ${lastErr ? lastErr.message : "unknown error"}`
    );
  }
}
