import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  importPrivateKeyFromJWK, 
  generateAESKey, 
  aesEncrypt, 
  wrapAESKey, 
  signData, 
  u8ToBase64 
} from '../utils/cryptoClient';

export default function SendTransaction() {
  const [senderId, setSenderId] = useState('');
  const [receiverId, setReceiverId] = useState('');
  const [amount, setAmount] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleSend(e) {
    e.preventDefault();
    setResult(null);
    setLoading(true);

    try {
      // 1. Obtener llave pública del servidor
      const pubRes = await fetch('http://localhost:4000/api/publicKey');
      if (!pubRes.ok) throw new Error('Error obteniendo la llave pública del servidor');
      const pubJson = await pubRes.json();
      const serverPubPem = pubJson.pem;

      // 2. Obtener llave privada local
      const privateJwkRaw = localStorage.getItem('privateKeyJwk');
      if (!privateJwkRaw) throw new Error('No se encontró la clave privada. Regístrate primero.');
      const privateJwk = JSON.parse(privateJwkRaw);
      const privateKey = await importPrivateKeyFromJWK(privateJwk);

      // 3. Preparar datos
      const trx = { 
        senderId: Number(senderId), 
        receiverId: Number(receiverId), 
        amount: Number(amount) 
      };
      const trxString = JSON.stringify(trx);

      // 4. Firmar (Integridad y Autenticidad)
      const signatureU8 = await signData(privateKey, trxString);
      const signatureB64 = u8ToBase64(signatureU8);

      // 5. Encriptar (Confidencialidad)
      const aesKey = await generateAESKey();
      const { iv, ciphertext } = await aesEncrypt(aesKey, trxString);
      const wrappedKeyU8 = await wrapAESKey(aesKey, serverPubPem);

      const body = {
        wrappedKey: u8ToBase64(wrappedKeyU8),
        iv: u8ToBase64(iv),
        ciphertext: u8ToBase64(ciphertext),
        signature: signatureB64,
        senderId: Number(senderId)
      };

      console.log("Sending body:", body);

      const resp = await fetch('http://localhost:4000/api/transaction/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });

      const j = await resp.json();
      setResult({ ok: resp.ok, response: j });

    } catch (err) {
      console.error(err);
      setResult({ ok: false, error: err.message });
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="send-container">
      <style>{`
        :root {
          --bg-body: #f3f4f6;
          --bg-card: #ffffff;
          --text-main: #111827;
          --text-muted: #6b7280;
          --primary: #111827;
          --border: #e5e7eb;
          --ring: rgba(17, 24, 39, 0.1);
          --radius: 12px;
          --code-bg: #f8fafc;
        }

        .send-container {
          min-height: 100vh;
          display: flex;
          align-items: center;
          justify-content: center;
          background-color: var(--bg-body);
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
          padding: 20px;
        }

        .card {
          background: var(--bg-card);
          width: 100%;
          max-width: 500px; /* Un poco más ancho para el JSON */
          padding: 40px;
          border-radius: var(--radius);
          box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 
                      0 8px 10px -6px rgba(0, 0, 0, 0.01);
        }

        .header {
          margin-bottom: 24px;
          text-align: center;
        }

        .title {
          font-size: 24px;
          font-weight: 700;
          color: var(--text-main);
          margin: 0 0 8px 0;
        }

        .subtitle {
          font-size: 14px;
          color: var(--text-muted);
          margin: 0;
        }

        .form-grid {
          display: grid;
          grid-template-columns: 1fr 1fr;
          gap: 16px;
          margin-bottom: 16px;
        }

        .form-group {
          margin-bottom: 16px;
        }
        
        .form-group.full-width {
          grid-column: 1 / -1;
        }

        .label {
          display: block;
          font-size: 13px;
          font-weight: 500;
          color: var(--text-main);
          margin-bottom: 8px;
        }

        .input {
          width: 100%;
          padding: 12px 16px;
          font-size: 15px;
          color: var(--text-main);
          background: #fff;
          border: 1px solid var(--border);
          border-radius: 8px;
          outline: none;
          transition: all 0.2s ease;
          box-sizing: border-box;
        }

        .input:focus {
          border-color: var(--primary);
          box-shadow: 0 0 0 4px var(--ring);
        }

        .btn-group {
          display: flex;
          gap: 12px;
          margin-top: 24px;
        }

        .btn {
          flex: 1;
          padding: 12px;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          border: none;
        }

        .btn-primary {
          background-color: var(--primary);
          color: white;
        }

        .btn-primary:hover:not(:disabled) {
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }

        .btn-secondary {
          background-color: transparent;
          color: var(--text-muted);
          border: 1px solid var(--border);
        }

        .btn-secondary:hover {
          background-color: #f9fafb;
          color: var(--text-main);
        }

        .btn:disabled {
          opacity: 0.7;
          cursor: wait;
        }

        /* Estilos para el resultado JSON */
        .result-container {
          margin-top: 24px;
          border-top: 1px solid var(--border);
          padding-top: 24px;
          animation: fadeIn 0.3s ease;
        }

        .status-badge {
          display: inline-block;
          padding: 4px 12px;
          border-radius: 99px;
          font-size: 12px;
          font-weight: 600;
          margin-bottom: 12px;
        }
        
        .status-success {
          background-color: #ecfdf5;
          color: #065f46;
        }
        
        .status-error {
          background-color: #fef2f2;
          color: #991b1b;
        }

        .code-block {
          background-color: var(--code-bg);
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 12px;
          overflow-x: auto;
          font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
          font-size: 12px;
          color: var(--text-main);
          line-height: 1.5;
        }

        @keyframes fadeIn {
          from { opacity: 0; transform: translateY(5px); }
          to { opacity: 1; transform: translateY(0); }
        }
      `}</style>

      <div className="card">
        <div className="header">
          <h2 className="title">Enviar Transacción</h2>
          <p className="subtitle">Transferencia segura encriptada E2E</p>
        </div>

        <form onSubmit={handleSend}>
          <div className="form-grid">
            <div className="form-group">
              <label className="label">ID Emisor</label>
              <input
                className="input"
                type="number"
                placeholder="Ej. 1"
                value={senderId}
                onChange={e => setSenderId(e.target.value)}
                required
              />
            </div>

            <div className="form-group">
              <label className="label">ID Receptor</label>
              <input
                className="input"
                type="number"
                placeholder="Ej. 2"
                value={receiverId}
                onChange={e => setReceiverId(e.target.value)}
                required
              />
            </div>
          </div>

          <div className="form-group">
            <label className="label">Monto a enviar</label>
            <input
              className="input"
              type="number"
              placeholder="0.00"
              value={amount}
              onChange={e => setAmount(e.target.value)}
              required
              step="0.01"
              min="0"
            />
          </div>

          <div className="btn-group">
            <button type="button" className="btn btn-secondary" onClick={() => navigate('/wallet')}>
              Cancelar
            </button>
            
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? 'Procesando...' : 'Enviar Fondos'}
            </button>
          </div>
        </form>

        {result && (
          <div className="result-container">
            <div className={`status-badge ${result.ok ? 'status-success' : 'status-error'}`}>
              {result.ok ? 'Transacción Exitosa' : 'Error en Transacción'}
            </div>

            <pre className="code-block">
              {JSON.stringify(result.response || { error: result.error }, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}