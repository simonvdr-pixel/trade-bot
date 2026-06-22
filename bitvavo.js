// ══════════════════════════════════════════════════════════════════
// BITVAVO WEBSOCKET CLIENT — TradeBot (gecorrigeerd)
// ══════════════════════════════════════════════════════════════════
// 100% WebSocket — geen CORS problemen, werkt direct in browser
// Docs: https://docs.bitvavo.com/docs/websocket-overview/
// WS:   wss://ws.bitvavo.com/v2
//
// BELANGRIJK — correcties t.o.v. vorige versie:
//  - Bitvavo gebruikt 'requestId' om verzoek en antwoord te koppelen
//    (niet '_id')
//  - Er bestaat geen 'getAccount' actie — gebruik 'getBalance' voor saldo
//  - Antwoorden komen terug als { action, response, requestId }
// ══════════════════════════════════════════════════════════════════

const BV_WS = 'wss://ws.bitvavo.com/v2';

const BV_SYMBOL_MAP = {
  'BTC/EUR':  'BTC-EUR',
  'ETH/EUR':  'ETH-EUR',
  'SOL/EUR':  'SOL-EUR',
  'XRP/EUR':  'XRP-EUR',
  'ADA/EUR':  'ADA-EUR',
  'DOGE/EUR': 'DOGE-EUR',
  'BNB/EUR':  'BNB-EUR',
  'AVAX/EUR': 'AVAX-EUR',
  'DOT/EUR':  'DOT-EUR',
  'LINK/EUR': 'LINK-EUR',
  'XLM/EUR':  'XLM-EUR',
  'RE/EUR':   'RE-EUR',
  'WLD/EUR':  'WLD-EUR',
  'SUI/EUR':  'SUI-EUR',
  'FET/EUR':  'FET-EUR',
  'ARX/EUR':  'ARX-EUR',
  'EIGEN/EUR':'EIGEN-EUR',
  'SYN/EUR':  'SYN-EUR',
  'HYPE/EUR': 'HYPE-EUR',
  'TAO/EUR':  'TAO-EUR',
};
const BV_SYMBOL_REV = Object.fromEntries(
  Object.entries(BV_SYMBOL_MAP).map(([k,v]) => [v,k])
);

// ── HMAC-SHA256 ───────────────────────────────────────────────────
async function hmacSHA256(secret, message) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', enc.encode(secret),
    { name:'HMAC', hash:'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, enc.encode(message));
  return Array.from(new Uint8Array(sig))
    .map(b => b.toString(16).padStart(2,'0')).join('');
}

// ══════════════════════════════════════════════════════════════════
class BitvavoClient {
  constructor({ apiKey, apiSecret }) {
    this.apiKey    = apiKey;
    this.apiSecret = apiSecret;
    this.ws        = null;
    this.connected = false;
    this.authenticated = false;

    // Callbacks
    this.onPrice      = null;
    this.onCandle     = null;
    this.onOrder      = null;
    this.onFill       = null;
    this.onError      = null;
    this.onConnect    = null;
    this.onDisconnect = null;
    this.onLog        = null; // optioneel: (msg) => {} voor debug

    this._pending  = {};   // requestId → {resolve, reject, timer}
    this._reqId    = 1;
    this._subQueue = [];
    this._reconnectTimer = null;
    this._destroyed = false;
  }

  _log(msg) { if (this.onLog) this.onLog(msg); console.log('[Bitvavo]', msg); }

  // ── Connect & authenticate ──────────────────────────────────────
  connect() {
    if (this.ws && this.ws.readyState < 2) return;
    this._destroyed = false;
    this.ws = new WebSocket(BV_WS);

    this.ws.onopen = async () => {
      this._log('WebSocket open, authenticeren...');
      const ts  = Date.now();
      const sig = await hmacSHA256(this.apiSecret, ts + 'GET/v2/websocket');
      this._send({
        action:    'authenticate',
        key:       this.apiKey,
        signature: sig,
        timestamp: ts,
        window:    10000,
      });
    };

    this.ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      this._handle(msg);
    };

    this.ws.onerror = () => {
      this._log('WebSocket fout');
      if (this.onError) this.onError('WebSocket verbindingsfout');
    };

    this.ws.onclose = (e) => {
      this._log(`WebSocket gesloten (code ${e.code})`);
      this.connected     = false;
      this.authenticated = false;
      if (this.onDisconnect) this.onDisconnect();
      if (!this._destroyed) {
        this._reconnectTimer = setTimeout(() => this.connect(), 4000);
      }
    };
  }

  _send(msg) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  // ── Request met requestId matching (DE FIX) ─────────────────────
  _request(action, params = {}) {
    return new Promise((resolve, reject) => {
      const requestId = this._reqId++;
      const timer = setTimeout(() => {
        delete this._pending[requestId];
        reject(new Error(`Timeout op actie '${action}' — geen antwoord van Bitvavo`));
      }, 10000);
      this._pending[requestId] = { resolve, reject, timer, action };

      const msg = { action, ...params, requestId };
      if (this.authenticated) {
        this._send(msg);
      } else {
        this._subQueue.push(msg);
      }
    });
  }

  // ── Handle incoming messages ────────────────────────────────────
  _handle(msg) {
    // 1. Authenticatie respons
    if (msg.event === 'authenticate') {
      if (msg.authenticated) {
        this.authenticated = true;
        this.connected     = true;
        this._log('Geauthenticeerd ✓');
        if (this.onConnect) this.onConnect();
        this._subQueue.forEach(m => this._send(m));
        this._subQueue = [];
      } else {
        this._log('Authenticatie mislukt: ' + JSON.stringify(msg));
        if (this.onError) this.onError('Authenticatie mislukt — controleer je API sleutels en of "Trading"/"View" rechten aanstaan');
      }
      return;
    }

    // 2. Foutmelding (met of zonder requestId)
    if (msg.errorCode !== undefined || msg.error) {
      const errText = msg.error || `Foutcode ${msg.errorCode}`;
      if (msg.requestId && this._pending[msg.requestId]) {
        const p = this._pending[msg.requestId];
        clearTimeout(p.timer);
        delete this._pending[msg.requestId];
        p.reject(new Error(errText));
      } else {
        this._log('Fout zonder requestId match: ' + errText);
        if (this.onError) this.onError(errText);
      }
      return;
    }

    // 3. Antwoord op een actie-verzoek (heeft requestId)
    if (msg.requestId !== undefined && this._pending[msg.requestId]) {
      const p = this._pending[msg.requestId];
      clearTimeout(p.timer);
      delete this._pending[msg.requestId];
      // Bitvavo wrapt data soms in { action, response }, soms direct
      p.resolve(msg.response !== undefined ? msg.response : msg);
      return;
    }

    // 4. Ticker (live price) — geen requestId, is een subscribe-event
    if (msg.event === 'ticker' && msg.market) {
      const ourSym = BV_SYMBOL_REV[msg.market];
      if (ourSym && msg.lastPrice && this.onPrice) {
        this.onPrice(ourSym, parseFloat(msg.lastPrice));
      }
      return;
    }

    // 5. Candle update
    if (msg.event === 'candle' && msg.market && msg.candle) {
      const ourSym = BV_SYMBOL_REV[msg.market];
      if (ourSym && this.onCandle) {
        const k = Array.isArray(msg.candle[0]) ? msg.candle[0] : msg.candle;
        this.onCandle(ourSym, {
          t: k[0], o: parseFloat(k[1]), h: parseFloat(k[2]),
          l: parseFloat(k[3]), c: parseFloat(k[4]), v: parseFloat(k[5]),
        });
      }
      return;
    }

    // 6. Subscribe-bevestiging (event: 'subscribed')
    if (msg.event === 'subscribed') {
      this._log('Subscriptie bevestigd: ' + JSON.stringify(msg.subscriptions || msg));
      return;
    }

    // 7. Order/fill events (account channel)
    if (msg.event === 'order' && this.onOrder) { this.onOrder(msg); return; }
    if (msg.event === 'fill'  && this.onFill)  { this.onFill(msg);  return; }

    // Onbekend event — loggen voor debug
    this._log('Onbehandeld bericht: ' + JSON.stringify(msg).slice(0,200));
  }

  // ══════════════════════════════════════════════════════════════
  // SUBSCRIPTIONS (geen requestId nodig, blijven open)
  // ══════════════════════════════════════════════════════════════

  subscribeTicker(ourSymbols) {
    const markets = ourSymbols.map(s => BV_SYMBOL_MAP[s]).filter(Boolean);
    if (!markets.length) return;
    const msg = { action:'subscribe', channels:[{ name:'ticker', markets }] };
    if (this.authenticated) this._send(msg); else this._subQueue.push(msg);
  }

  subscribeCandles(ourSymbols, interval = '5m') {
    const markets = ourSymbols.map(s => BV_SYMBOL_MAP[s]).filter(Boolean);
    if (!markets.length) return;
    const msg = { action:'subscribe', channels:[{ name:'candles', interval:[interval], markets }] };
    if (this.authenticated) this._send(msg); else this._subQueue.push(msg);
  }

  subscribeAccount(ourSymbols) {
    const markets = ourSymbols.map(s => BV_SYMBOL_MAP[s]).filter(Boolean);
    if (!markets.length) return;
    const msg = { action:'subscribe', channels:[{ name:'account', markets }] };
    if (this.authenticated) this._send(msg); else this._subQueue.push(msg);
  }

  // ══════════════════════════════════════════════════════════════
  // ACCOUNT ACTIES (vereisen auth) — gecorrigeerde actienamen
  // ══════════════════════════════════════════════════════════════

  // Saldo ophalen — DE FIX: 'getBalance' bestaat, 'getAccount' niet
  async getAllBalances() {
    const res = await this._request('getBalance', {});
    return Array.isArray(res) ? res : (res?.response || []);
  }

  async getBalance(symbol) {
    const res = await this._request('getBalance', symbol ? { symbol } : {});
    const arr = Array.isArray(res) ? res : (res?.response || []);
    if (symbol) return arr.find(b => b.symbol === symbol) || null;
    return arr;
  }

  // Account fee-info (REST: GET /account)
  async getAccountFees() {
    try {
      const res = await this._request('getAccount', {});
      return res;
    } catch {
      // Sommige Bitvavo API-versies kennen geen WS-actie voor fees — geef leeg terug
      return null;
    }
  }

  // ── Prijs via orderbook (depth 1) ───────────────────────────────
  async getPrice(ourSymbol) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error(`Onbekend paar: ${ourSymbol}`);
    const res = await this._request('getBook', { market, depth: 1 });
    const book = res?.response || res;
    const bids = book.bids || [];
    const asks = book.asks || [];
    if (asks.length) return parseFloat(asks[0][0]);
    if (bids.length) return parseFloat(bids[0][0]);
    throw new Error('Geen prijs beschikbaar in orderboek');
  }

  // ── Candle geschiedenis ──────────────────────────────────────────
  async getCandles(ourSymbol, interval = '5m', limit = 200) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) return [];
    const res = await this._request('getCandles', { market, interval, limit });
    const data = res?.response || res;
    if (!Array.isArray(data)) return [];
    return data.map(k => ({
      t: k[0], o: parseFloat(k[1]), h: parseFloat(k[2]),
      l: parseFloat(k[3]), c: parseFloat(k[4]), v: parseFloat(k[5]),
    })).reverse();
  }

  // ══════════════════════════════════════════════════════════════
  // ORDERS (vereisen auth, alleen in live modus)
  // ══════════════════════════════════════════════════════════════

  async marketBuy(ourSymbol, amountInEur) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error(`Onbekend paar: ${ourSymbol}`);
    if (amountInEur < 5) throw new Error('Minimum ordergrootte is €5');
    const res = await this._request('privateCreateOrder', {
      market,
      side:        'buy',
      orderType:   'market',
      amountQuote: amountInEur.toFixed(2),
      operatorId:  1001, // verplicht veld sinds 2024
    });
    return res?.response || res;
  }

  async marketSell(ourSymbol, amount) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error(`Onbekend paar: ${ourSymbol}`);
    const rounded = parseFloat(amount.toFixed(8));
    if (rounded <= 0) throw new Error('Hoeveelheid te klein');
    const res = await this._request('privateCreateOrder', {
      market,
      side:       'sell',
      orderType:  'market',
      amount:     rounded.toString(),
      operatorId: 1001,
    });
    return res?.response || res;
  }

  async getOpenOrders(ourSymbol) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    const res = await this._request('privateGetOrdersOpen', market ? { market } : {});
    return res?.response || res;
  }

  async cancelOrder(ourSymbol, orderId) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error('Onbekend paar');
    const res = await this._request('privateCancelOrder', { market, orderId });
    return res?.response || res;
  }

  async getMyTrades(ourSymbol, limit = 50) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) return [];
    const res = await this._request('privateGetTrades', { market, limit });
    return res?.response || res || [];
  }

  // ── Clean disconnect ────────────────────────────────────────────
  disconnect() {
    this._destroyed = true;
    clearTimeout(this._reconnectTimer);
    if (this.ws) { try { this.ws.close(); } catch {} this.ws = null; }
    this.connected     = false;
    this.authenticated = false;
  }
}

window.BitvavoClient      = BitvavoClient;
window.BITVAVO_SYMBOL_MAP = BV_SYMBOL_MAP;
window.BITVAVO_SYMBOL_REV = BV_SYMBOL_REV;
