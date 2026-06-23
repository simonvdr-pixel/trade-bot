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
  // BELANGRIJK: Bitvavo stuurt GEEN bevestigingsbericht terug bij
  // succesvolle authenticatie — alleen bij een FOUT komt er een
  // foutmelding terug. We wachten daarom kort op een mogelijke fout;
  // komt die niet, dan gaan we uit van een geslaagde authenticatie.
  connect() {
    if (this.ws && this.ws.readyState < 2) return;
    this._destroyed = false;
    this.ws = new WebSocket(BV_WS);
    this._authConfirmed = false;

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

      // Geen expliciete bevestiging te verwachten — neem na korte
      // stilte (1.2s zonder foutmelding) aan dat auth is geslaagd.
      this._authFallbackTimer = setTimeout(() => {
        if (!this._authConfirmed && !this._destroyed) {
          this._log('Geen foutmelding ontvangen → authenticatie geslaagd');
          this.authenticated = true;
          this.connected     = true;
          this._authConfirmed = true;
          if (this.onConnect) this.onConnect();
          this._subQueue.forEach(m => this._send(m));
          this._subQueue = [];
        }
      }, 1200);
    };

    this.ws.onmessage = (e) => {
      let msg;
      try { msg = JSON.parse(e.data); } catch { return; }
      this._log('← ' + e.data.slice(0, 150));
      // Bitvavo stuurt soms een array van berichten (bv. meerdere balances)
      if (Array.isArray(msg)) {
        msg.forEach(m => this._handle(m));
      } else {
        this._handle(msg);
      }
    };

    this.ws.onerror = () => {
      this._log('WebSocket fout');
      if (this.onError) this.onError('WebSocket verbindingsfout');
    };

    this.ws.onclose = (e) => {
      this._log(`WebSocket gesloten (code ${e.code})`);
      clearTimeout(this._authFallbackTimer);
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

  // ── Request met requestId matching + verzamelen van losse berichten ──
  // Bitvavo stuurt voor sommige acties (bv. privateGetBalance zonder
  // 'symbol' filter) één los bericht PER asset, elk met dezelfde requestId.
  // We verzamelen alle berichten met die requestId en resolven na een
  // korte stilte (300ms zonder nieuw bericht voor die id).
  _request(action, params = {}) {
    return new Promise((resolve, reject) => {
      const requestId = this._reqId++;
      const timer = setTimeout(() => {
        delete this._pending[requestId];
        reject(new Error(`Timeout op actie '${action}' — geen antwoord van Bitvavo`));
      }, 10000);
      this._pending[requestId] = { resolve, reject, timer, action, buffer:[], settleTimer:null };

      const msg = { action, ...params, requestId };
      if (this.authenticated) {
        this._send(msg);
      } else {
        this._subQueue.push(msg);
      }
    });
  }

  // Voeg een resultaat toe aan de buffer van een pending request en
  // resolve zodra er even niets meer binnenkomt (debounce 250ms)
  _bufferResult(requestId, value) {
    const p = this._pending[requestId];
    if (!p) return;
    p.buffer.push(value);
    clearTimeout(p.settleTimer);
    p.settleTimer = setTimeout(() => {
      clearTimeout(p.timer);
      delete this._pending[requestId];
      // Eén bericht → geef direct het object terug, anders de hele array
      p.resolve(p.buffer.length === 1 ? p.buffer[0] : p.buffer);
    }, 250);
  }

  // ── Handle incoming messages ────────────────────────────────────
  _handle(msg) {
    // 1. Authenticatie respons — als die WEL binnenkomt (sommige
    //    momenten/versies van de API doen dit blijkbaar toch)
    if (msg.event === 'authenticate' || (msg.action === 'authenticate')) {
      clearTimeout(this._authFallbackTimer);
      this._authConfirmed = true;
      if (msg.authenticated !== false) {
        this.authenticated = true;
        this.connected     = true;
        this._log('Geauthenticeerd ✓ (expliciete bevestiging)');
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
        clearTimeout(p.settleTimer);
        delete this._pending[msg.requestId];
        p.reject(new Error(errText));
      } else {
        this._log('Fout zonder requestId match: ' + errText);
        if (this.onError) this.onError(errText);
      }
      return;
    }

    // 3. Antwoord op een actie-verzoek (heeft requestId) — verzamel in buffer
    if (msg.requestId !== undefined && this._pending[msg.requestId]) {
      const value = msg.response !== undefined ? msg.response : msg;
      this._bufferResult(msg.requestId, value);
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
    const res = await this._request('privateGetBalance', {});
    if (Array.isArray(res)) return res;
    if (res && res.symbol) return [res]; // één los balance-object
    return [];
  }

  async getBalance(symbol) {
    const res = await this._request('privateGetBalance', symbol ? { symbol } : {});
    let arr;
    if (Array.isArray(res)) arr = res;
    else if (res && res.symbol) arr = [res];
    else arr = [];
    if (symbol) return arr.find(b => b.symbol === symbol) || null;
    return arr;
  }

  // Account fee-info (REST: GET /account)
  async getAccountFees() {
    try {
      const res = await this._request('getAccountFees', {});
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

  // ── Alle huidige prijzen in één keer ophalen ────────────────────
  // Gebruik dit direct na verbinden, zodat je niet moet wachten tot
  // de ticker-subscriptie toevallig een prijswijziging doorstuurt.
  async getAllTickerPrices() {
    const res = await this._request('getTickerPrice', {});
    const data = Array.isArray(res) ? res : (res ? [res] : []);
    const result = {};
    data.forEach(t => {
      const ourSym = BV_SYMBOL_REV[t.market];
      if (ourSym && t.price) result[ourSym] = parseFloat(t.price);
    });
    return result;
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

  // ── Marktinfo ophalen (precisie per coin) — DE FIX voor decimalen ──
  // Bitvavo heeft per markt een eigen 'quantityDecimals' instelling
  // (vroeger ten onrechte 'amountPrecision' genoemd in deze code).
  // We cachen dit zodat we niet steeds opnieuw moeten vragen.
  async getMarketInfo(ourSymbol) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error(`Onbekend paar: ${ourSymbol}`);
    if (!this._marketCache) this._marketCache = {};
    if (this._marketCache[market]) return this._marketCache[market];

    const res = await this._request('getMarkets', { market });
    const data = Array.isArray(res) ? res[0] : res;
    const info = {
      // DE FIX: het juiste veld heet 'quantityDecimals', niet 'amountPrecision'
      amountPrecision:  data?.quantityDecimals !== undefined ? parseInt(data.quantityDecimals) : 6,
      pricePrecision:   data?.pricePrecision   !== undefined ? parseInt(data.pricePrecision)   : 5,
      notionalDecimals: data?.notionalDecimals !== undefined ? parseInt(data.notionalDecimals) : 2,
      minOrderInBaseAsset:  data?.minOrderInBaseAsset  || '0',
      minOrderInQuoteAsset: data?.minOrderInQuoteAsset || '5',
    };
    this._marketCache[market] = info;
    return info;
  }

  // Rond een hoeveelheid af naar het juiste aantal decimalen voor deze markt
  _roundAmount(amount, precision) {
    const factor = Math.pow(10, precision);
    // Math.floor i.p.v. afronden, zodat we nooit MEER bezitten dan we afronden
    // (voorkomt "insufficient balance" bij verkopen door afrondingsfouten)
    return Math.floor(amount * factor) / factor;
  }

  // ══════════════════════════════════════════════════════════════
  // ORDERS (vereisen auth, alleen in live modus)
  // ══════════════════════════════════════════════════════════════

  async marketBuy(ourSymbol, amountInEur) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error(`Onbekend paar: ${ourSymbol}`);
    if (amountInEur < 5) throw new Error('Minimum ordergrootte is €5');

    // notionalDecimals voor het EUR-bedrag opvragen (meestal 2, niet gegarandeerd)
    let notionalDecimals = 2;
    try {
      const info = await this.getMarketInfo(ourSymbol);
      notionalDecimals = info.notionalDecimals;
    } catch {
      this._log('Kon notionalDecimals niet ophalen, val terug op 2 decimalen');
    }

    const res = await this._request('privateCreateOrder', {
      market,
      side:        'buy',
      orderType:   'market',
      amountQuote: amountInEur.toFixed(notionalDecimals),
      operatorId:  1001, // verplicht veld sinds 2024
    });
    return res?.response || res;
  }

  async marketSell(ourSymbol, amount) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error(`Onbekend paar: ${ourSymbol}`);

    // Haal de juiste decimale precisie op voor DEZE markt (DE FIX)
    let precision = 6;
    try {
      const info = await this.getMarketInfo(ourSymbol);
      precision = info.amountPrecision;
    } catch {
      this._log('Kon marktprecisie niet ophalen, val terug op 6 decimalen');
    }

    const rounded = this._roundAmount(amount, precision);
    if (rounded <= 0) throw new Error('Hoeveelheid te klein na afronding');

    // toFixed met de juiste precisie i.p.v. vaste 8 decimalen
    const amountStr = rounded.toFixed(precision);

    const res = await this._request('privateCreateOrder', {
      market,
      side:       'sell',
      orderType:  'market',
      amount:     amountStr,
      operatorId: 1001,
    });
    return res?.response || res;
  }

  // DE FIX: de juiste actie heet 'privateGetOrdersOpen', niet 'getOrders'
  // met een status-filter — die laatste bestaat niet als losse actie.
  async getOpenOrders(ourSymbol) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    const res = await this._request('privateGetOrdersOpen', market ? { market } : {});
    const data = res?.response || res;
    return Array.isArray(data) ? data : (data ? [data] : []);
  }

  // DE FIX: 'privateCancelOrder', niet 'cancelOrder' (die mist het
  // verplichte 'private'-voorvoegsel voor geauthenticeerde acties)
  async cancelOrder(ourSymbol, orderId) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) throw new Error('Onbekend paar');
    const res = await this._request('privateCancelOrder', { market, orderId, operatorId: 1001 });
    return res?.response || res;
  }

  async getMyTrades(ourSymbol, limit = 50) {
    const market = BV_SYMBOL_MAP[ourSymbol];
    if (!market) return [];
    const res = await this._request('getTradeHistory', { market, limit });
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
