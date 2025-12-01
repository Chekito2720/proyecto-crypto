import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { generateKeyPair, exportPublicKeyToPEM, exportPrivateKeyJWK } from '../utils/cryptoClient';

export default function Register() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [msg, setMsg] = useState('');
  const [status, setStatus] = useState(''); // 'success' | 'error'
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  async function handleRegister(e) {
    e.preventDefault();
    setMsg('');
    setStatus('');
    setLoading(true);

    try {
      // 1. Generar llaves (esto puede tardar un poco)
      const kp = await generateKeyPair();
      const publicPem = await exportPublicKeyToPEM(kp.publicKey);
      const privateJwk = await exportPrivateKeyJWK(kp.privateKey);

      // 2. Enviar al backend
      const res = await fetch('http://localhost:4000/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password, publicKeyPem: publicPem })
      });
      
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || JSON.stringify(j));

      // 3. Guardar llave privada (Demo)
      localStorage.setItem('privateKeyJwk', JSON.stringify(privateJwk));
      
      setStatus('success');
      setMsg('Cuenta creada exitosamente. Redirigiendo...');
      
      // Redirigir al usuario después de un momento para que lea el mensaje
      setTimeout(() => {
        navigate('/'); // O a /login
      }, 1500);

    } catch (err) {
      setStatus('error');
      setMsg('Error: ' + err.message);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="register-container">
      {/* Estilos idénticos al Login para mantener consistencia visual */}
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
        }

        .register-container {
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
          max-width: 400px;
          padding: 40px;
          border-radius: var(--radius);
          box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.05), 
                      0 8px 10px -6px rgba(0, 0, 0, 0.01);
        }

        .title {
          font-size: 24px;
          font-weight: 700;
          color: var(--text-main);
          margin-bottom: 8px;
          text-align: center;
          letter-spacing: -0.025em;
        }
        
        .subtitle {
          font-size: 14px;
          color: var(--text-muted);
          text-align: center;
          margin-bottom: 32px;
        }

        .form-group {
          margin-bottom: 20px;
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

        .btn {
          width: 100%;
          padding: 12px;
          border-radius: 8px;
          font-size: 14px;
          font-weight: 600;
          cursor: pointer;
          transition: all 0.2s;
          border: none;
          background-color: var(--primary);
          color: white;
          margin-top: 12px;
        }

        .btn:hover:not(:disabled) {
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .btn:disabled {
          opacity: 0.7;
          cursor: not-allowed;
        }

        .footer-links {
          display: flex;
          justify-content: center;
          gap: 6px;
          margin-top: 24px;
          font-size: 14px;
          color: var(--text-muted);
        }

        .link {
          color: var(--primary);
          font-weight: 600;
          text-decoration: none;
        }
        
        .link:hover {
          text-decoration: underline;
        }

        .msg-box {
          margin-top: 20px;
          padding: 12px;
          border-radius: 8px;
          font-size: 13px;
          text-align: center;
          font-weight: 500;
        }
        
        .msg-success {
          background-color: #ecfdf5;
          color: #065f46;
        }
        
        .msg-error {
          background-color: #fef2f2;
          color: #991b1b;
        }
      `}</style>

      <div className="card">
        <h2 className="title">Crear cuenta</h2>
        <p className="subtitle">Generaremos tus llaves de seguridad automáticamente</p>

        <form onSubmit={handleRegister}>
          <div className="form-group">
            <label className="label">Correo electrónico</label>
            <input 
              className="input"
              placeholder="tu@email.com" 
              type="email"
              value={email} 
              onChange={e=>setEmail(e.target.value)} 
              required
            />
          </div>
          
          <div className="form-group">
            <label className="label">Contraseña</label>
            <input 
              className="input"
              placeholder="Crea una contraseña segura" 
              type="password" 
              value={password} 
              onChange={e=>setPassword(e.target.value)} 
              required
            />
          </div>

          <button type="submit" className="btn" disabled={loading}>
            {loading ? 'Generando llaves...' : 'Registrarse'}
          </button>
        </form>

        <div className="footer-links">
          <span>¿Ya tienes cuenta?</span>
          <Link to="/" className="link">Inicia sesión</Link>
        </div>

        {msg && (
          <div className={`msg-box ${status === 'success' ? 'msg-success' : 'msg-error'}`}>
            {msg}
          </div>
        )}
      </div>
    </div>
  );
}