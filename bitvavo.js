// ══════════════════════════════════════════════════════════════════
// BITVAVO WEBSOCKET CLIENT — TradeBot
// ══════════════════════════════════════════════════════════════════
// 100% WebSocket — geen CORS problemen, werkt direct in browser
// Docs: https://docs.bitvavo.com/#tag/WebSocket
// WS:   wss://ws.bitvavo.com/v2
// ══════════════════════════════════════════════════════════════════

const BV_WS = 'wss://ws.bitvavo.com/v2';

const BV_SYMBOL_MAP = {
  // Major coins
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
  // Toegevoegd vanuit jouw portfolio
  'XLM/EUR':  'XLM-EUR',   // Stellar
  'RE/EUR':   'RE-EUR',    // Re Protocol
  'WLD/EUR':  'WLD-EUR',   // Worldcoin
  'SUI/EUR':  'SUI-EUR',   // Sui
  'FET/EUR':  'FET-EUR',   // Fetch.ai
  'ARX/EUR':  'ARX-EUR',   // Arcium
  'EIGEN/EUR':'EIGEN-EUR', // EigenLayer
  'SYN/EUR':  'SYN-EUR',   // Synapse
  'HYPE/EUR': 'HYPE-EUR',  // Hyperliquid
  'TAO/EUR':  'TAO-EUR',   // Bittensor
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
    this.onPrice      = null;  // (ourSymbol, price) => {}
    this.onCandle     = null;  // (ourSymbol, candle) => {}
    this.onOrder      = null;  // (orderData) => {}
    this.onFill       = null;  // (fillData) => {}
    this.onBalance    = null;  // (balances) => {}
    this.onError      = null;  // (msg) => {}
    this.onConnect    = null;  // () => {}
    this.onDisconnect = null;  // () => {}

    // Pending requests (id → {resolve, reject})
    this._pending  = {};
    this._msgId    = 1;
    this._subQueue = [];      // messages to send after auth
    this._reconnectTimer = null;
    this._destroyed = false;
  }

  // ── Connect & authenticate ──────────────────────────────────────
  connect() {
    if (this.ws && this.ws.readyState < 2) return;
    this._destroyed = false;
    this.ws = new WebSocket(BV_WS);

    this.ws.onopen = async () => {
      console.log('[Bitvavo WS] Verbonden');
      // Authenticate
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
      if (this.onError) this.onError('WebSocket verbindingsfout');
    };

    this.ws.onclose = () => {
      this.connected     = false;
      this.authenticated = false;
      if (this.onDisconnect) this.onDisconnect();
      if (!this._destroyed) {
        console.log('[Bitvavo WS] Herverbinden over 4s...');
        this._reconnectTimer = setTimeout(() => this.connect(), 4000);
      }
    };
  }

  // ── Send a message ──────────────────────────────────────────────
  _send(msg) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(msg));
    }
  }

  // ── Send with response promise (for account/order calls) ────────
  _request(payload) {
    return new Promise((resolve, reject) => {
      const id = this._msgId++;
      this._pending[id] = { resolve, reject };
      const timer = setTimeout(() => {
        delete this._pending[id];
        reject(new Error('Timeout — geen antwoord van Bitvavo'));
      }, 10000);
      this._pending[id].timer = timer;

      const msg = { ...payload, _id: id };
      if (this.authenticated) {
        this._send(msg);
      } else {
        this._subQueue.push(msg);
      }
    });
  }

  // ── Handle incoming messages ────────────────────────────────────
  _handle(msg) {
    // Auth response
    if (msg.event === 'authenticate') {
      if (msg.authenticated) {
        this.authenticated = true;
        this.connected     = true;
        console.log('[Bitvavo WS] Geauthenticeerd ✓');
        if (this.onConnect) this.onConnect();
        // Flush queued messages
        this._subQueue.forEach(m => this._send(m));
        this._subQueue = [];
      } else {
        if (this.onError) this.onError('Authenticatie mislukt — controleer je API sleutels');
      }
      return;
    }

    // Error
    if (msg.error || msg.errorCode) {
      const errMsg = msg.error || `code ${msg.errorCode}`;
      // Resolve pending request with error
      if (msg._id && this._pending[msg._id]) {
        const p = this._pending[msg._id];
        clearTimeout(p.timer);
        delete this._pending[msg._id];
        p.reject(new Error(errMsg));
      } else {
        if (this.onError) this.onError(errMsg);
      }
      return;
    }

    // Response to a request (_id present)
    if (msg._id && this._pending[msg._id]) {
      const p = this._pending[msg._id];
      clearTimeout(p.timer);
      delete this._pending[msg._id];
      p.resolve(msg);
      return;
    }

    // Ticker (live price)
    if (msg.event === 'ticker' && msg.market) {
      const ourSym = BV_SYMBOL_REV[msg.market];
      if (ourSym && msg.lastPrice && this.onPrice) {
        this.onPrice(ourSym, parseFloat(msg.lastPrice));
      }
      return;
    }

    // Candle update
    if (msg.event === 'candle' && msg.market && msg.candle) {
      const ourSym = BV_SYMBOL_REV[msg.market];
      if (ourSym && this.onCandle) {
        const k = Array.isArray(msg.candle[0]) ? msg.candle[0] : msg.candle;
        this.onCandle(ourSym, {
          t: k[0],
          o: parseFloat(k[1]),
          h: parseFloat(k[2]),
          l: parseFloat(k[3]),
          c: parseFloat(k[4]),
          v: parseFloat(k[5]),
        });
      }
      return;
    }

    // Account order update
    if (msg.event === 'order' && this.onOrder) {
      this.onOrder(msg);
      return;
    }

    // Fill (trade executed)
    if (msg.event === 'fill' && this.onFill) {
      this.onFill(msg);
      return;
    }

    // Balance update after order
    if (msg.event === 'account' && this.onBalance) {
      this.onBalance(msg);
      return;
    }
  }

  // ══════════════════════════════════════════════════════════════
  // PUBLIC DATA (no auth needed — subscribe without auth too)
  // ══════════════════════════════════════════════════════════════

  // Live ticker prices for multiple pairs
  subscribeTicker(ourSymbols) {
    const markets = ourSymbols.map(s => BV_SYMBOL_MAP[s]).filter(Boolean);
    const msg = { action:'subscribe', channels:[{ name:'ticker', markets }] };
    if (this.authenticated) this._send(msg);
    else this._subQueue.push(msg);
  }

  // Live candle updates
  subscribeCandles(ourSymbols, interval = '5m') {
    const markets = ourSymbols.map(s => BV_SYMBOL_MAP[s]).filter(Boolean);
    const msg = { action:'subscribe', channels:[{ name:'candles', interval:[interval], markets }] };
    if (this.authenticated) this._send(msg);
    else this._subQueue.push(msg);
  }

  // Account order/fill stream
  subscribeAccount(ourSymbols) {
    const markets = ourSymbols.map(s => BV_SYMBOL_MAP[s]).filter(Boolean);
    const msg = { action:'subscribe', channels:[{ name:'account', markets }] };
    if (this.authenticated) this._send(msg);
    else this._subQueue.push(msg);
  }

  // ══════════════════════════════════════════════════════════════
  // ACCOUNT (requires auth)
  // ══════════════════════════════════════════════════════════════

  async getAccount() {
    const res = await this._request({ action:'getAccount' });
    return res;
  }

  async getBalance(symbol = null) {
    const payload = { action:'getBalance' };
    if (symbol) payload.symbol = symbol;
    const res = await this._request(payload);
    return res.response || res.balance || res;
  }

  async getAllBalances() {
    const res = await this._request({ action:'getBalance' });
    const data = res.response || res;
    return Array.isArray(data) ? data : [];
  }

  // ── Get current price via WS ────────────────────────────────────
  async getPrice(ourSymbol) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error(`Onbekend paar: ${ourSymbol}`);
    const res = await this._request({ action:'getBook', market, depth:1 });
    // Use best bid/ask midpoint
    const bids = res.bids || [];
    const asks = res.asks || [];
    if (asks.length) return parseFloat(asks[0][0]);
    if (bids.length) return parseFloat(bids[0][0]);
    throw new Error('Geen prijs beschikbaar');
  }

  // ── Get candle history via WS ───────────────────────────────────
  async getCandles(ourSymbol, interval = '5m', limit = 200) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) return [];
    const res = await this._request({ action:'getCandles', market, interval, limit });
    const data = res.response || res.candles || res;
    if (!Array.isArray(data)) return [];
    return data.map(k => ({
      t: k[0],
      o: parseFloat(k[1]),
      h: parseFloat(k[2]),
      l: parseFloat(k[3]),
      c: parseFloat(k[4]),
      v: parseFloat(k[5]),
    })).reverse();
  }

  // ══════════════════════════════════════════════════════════════
  // ORDERS (requires auth, only in live mode)
  // ══════════════════════════════════════════════════════════════

  async marketBuy(ourSymbol, amountInEur) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error(`Onbekend paar: ${ourSymbol}`);
    if (amountInEur < 5) throw new Error('Minimum ordergrootte is €5');
    const res = await this._request({
      action:      'privateCreateOrder',
      market,
      side:        'buy',
      orderType:   'market',
      amountQuote: amountInEur.toFixed(2),
    });
    return res.response || res;
  }

  async marketSell(ourSymbol, amount) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error(`Onbekend paar: ${ourSymbol}`);
    const rounded = parseFloat(amount.toFixed(8));
    if (rounded <= 0) throw new Error('Hoeveelheid te klein');
    const res = await this._request({
      action:    'privateCreateOrder',
      market,
      side:      'sell',
      orderType: 'market',
      amount:    rounded.toString(),
    });
    return res.response || res;
  }

  async getOpenOrders(ourSymbol) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    const payload = { action:'privateGetOrdersOpen' };
    if (market) payload.market = market;
    const res = await this._request(payload);
    return res.response || res;
  }

  async cancelOrder(ourSymbol, orderId) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error('Onbekend paar');
    const res = await this._request({ action:'privateCancelOrder', market, orderId });
    return res.response || res;
  }

  async getMyTrades(ourSymbol, limit = 50) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) return [];
    const res = await this._request({ action:'privateGetTrades', market, limit });
    return res.response || res || [];
  }

  // ── Clean disconnect ────────────────────────────────────────────
  disconnect() {
    this._destroyed = true;
    clearTimeout(this._reconnectTimer);
    if (this.ws) {
      try { this.ws.close(); } catch {}
      this.ws = null;
    }
    this.connected     = false;
    this.authenticated = false;
  }
}

// ── Public price feed (NO auth needed) ───────────────────────────
// For paper trading without API keys — uses public WS ticker only
class BitvavoPublicFeed {
  constructor() {
    this.ws      = null;
    this.onPrice = null;
    this._destroyed = false;
  }

  connect(ourSymbols) {
    this._destroyed = false;
    this.ws = new WebSocket(BV_WS);

    this.ws.onopen = () => {
      const markets = ourSymbols.map(s => BV_SYMBOL_MAP[s]).filter(Boolean);
      this.ws.send(JSON.stringify({
        action:   'subscribe',
        channels: [{ name:'ticker', markets }],
      }));
      console.log('[Bitvavo Public] Verbonden, ticker geabonneerd');
    };

    this.ws.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.event === 'ticker' && msg.market && msg.lastPrice) {
          const ourSym = BV_SYMBOL_REV[msg.market];
          if (ourSym && this.onPrice) this.onPrice(ourSym, parseFloat(msg.lastPrice));
        }
      } catch {}
    };

    this.ws.onclose = () => {
      if (!this._destroyed) {
        setTimeout(() => this.connect(ourSymbols), 4000);
      }
    };

    this.ws.onerror = () => {};
  }

  disconnect() {
    this._destroyed = true;
    if (this.ws) { try { this.ws.close(); } catch {} }
  }
}

window.BitvavoClient     = BitvavoClient;
window.BitvavoPublicFeed = BitvavoPublicFeed;
window.BITVAVO_SYMBOL_MAP = BV_SYMBOL_MAP;
window.BITVAVO_SYMBOL_REV = BV_SYMBOL_REV;
