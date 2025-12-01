import React from 'react';
import { useNavigate } from 'react-router-dom';

export default function Wallet() {
  const navigate = useNavigate();

  function handleSend() {
    navigate('/send');
  }

  function handleLogout() {
    // Limpiamos el token (opcional, pero buena práctica en UI de wallet)
    localStorage.removeItem('token');
    localStorage.removeItem('privateKeyJwk');
    navigate('/');
  }

  return (
    <div className="wallet-container">
      <style>{`
        :root {
          --bg-body: #f3f4f6;
          --bg-card: #ffffff;
          --text-main: #111827;
          --text-muted: #6b7280;
          --primary: #111827;
          --border: #e5e7eb;
          --radius: 12px;
          --accent-bg: #f9fafb; /* Fondo para cajas de info */
        }

        .wallet-container {
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
          max-width: 420px;
          padding: 40px;
          border-radius: var(--radius);
          box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 
                      0 8px 10px -6px rgba(0, 0, 0, 0.01);
          text-align: center; /* Centramos el contenido para esta vista */
        }

        .header {
          margin-bottom: 32px;
        }

        .title {
          font-size: 26px;
          font-weight: 700;
          color: var(--text-main);
          margin: 0 0 8px 0;
          letter-spacing: -0.025em;
        }

        .subtitle {
          font-size: 15px;
          color: var(--text-muted);
          margin: 0;
        }

        /* Caja de información estilo "Dashboard" */
        .info-box {
          background-color: var(--accent-bg);
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 16px;
          margin-bottom: 32px;
          text-align: left;
        }

        .info-label {
          font-size: 12px;
          text-transform: uppercase;
          letter-spacing: 0.05em;
          color: var(--text-muted);
          font-weight: 600;
          margin-bottom: 4px;
          display: block;
        }

        .info-text {
          font-size: 14px;
          color: var(--text-main);
          line-height: 1.5;
          margin: 0;
        }

        .actions {
          display: flex;
          flex-direction: column;
          gap: 12px;
        }

        .btn {
          width: 100%;
          padding: 14px;
          border-radius: 8px;
          font-size: 15px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          border: none;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
        }

        .btn-primary {
          background-color: var(--primary);
          color: white;
        }

        .btn-primary:hover {
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        }

        .btn-secondary {
          background-color: transparent;
          color: var(--text-muted);
          border: 1px solid transparent;
        }

        .btn-secondary:hover {
          color: var(--text-main);
          background-color: #f9fafb;
          border-color: var(--border);
        }

        /* Simulación de un balance grande */
        .balance-display {
          margin: 30px 0;
        }
        
        .balance-amount {
          font-size: 36px;
          font-weight: 800;
          color: var(--text-main);
        }
        
        .balance-unit {
          font-size: 16px;
          color: var(--text-muted);
          font-weight: 500;
          margin-left: 4px;
        }
      `}</style>

      <div className="card">
        <div className="header">
          <h2 className="title">Mi Billetera</h2>
          <p className="subtitle">Panel de control</p>
        </div>

        {/* Agregué esto visualmente para que parezca una wallet real */}
        <div className="balance-display">
          <span className="balance-amount">0.00</span>
          <span className="balance-unit">ETH</span>
        </div>

        <div className="info-box">
          <span className="info-label">Estado del sistema</span>
          <p className="info-text">
            Modo Demo activo. Puedes firmar transacciones localmente y enviarlas usando el botón inferior.
          </p>
        </div>

        <div className="actions">
          <button onClick={handleSend} className="btn btn-primary">
            Nueva Transferencia
          </button>
          
          <button onClick={handleLogout} className="btn btn-secondary">
            Cerrar sesión
          </button>
        </div>
      </div>
    </div>
  );
}