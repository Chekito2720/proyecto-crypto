import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';

export default function Login() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [msg, setMsg] = useState('');
  const [status, setStatus] = useState(''); // 'success' | 'error'
  const navigate = useNavigate();

  async function handleLogin(e) {
    e.preventDefault();
    setMsg('');
    setStatus('');

    try {
      const res = await fetch('http://localhost:4000/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error || JSON.stringify(j));
      
      localStorage.setItem('token', j.token);
      setMsg('Bienvenido');
      setStatus('success');
      
      // Pequeña pausa para ver el mensaje de éxito
      setTimeout(() => navigate('/wallet'), 800);
      
    } catch (err) {
      setMsg(err.message || 'Error al iniciar sesión');
      setStatus('error');
    }
  }

  return (
    <div className="login-container">
      {/* Estilos CSS inyectados directamente en el componente */}
      <style>{`
        :root {
          --bg-body: #f3f4f6;
          --bg-card: #ffffff;
          --text-main: #111827;
          --text-muted: #6b7280;
          --primary: #111827; /* Negro suave elegante */
          --border: #e5e7eb;
          --ring: rgba(17, 24, 39, 0.1);
          --radius: 12px;
        }

        .login-container {
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
          margin-bottom: 32px;
          text-align: center;
          letter-spacing: -0.025em;
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
          box-sizing: border-box; /* Importante para que el padding no rompa el ancho */
        }

        .input::placeholder {
          color: #9ca3af;
        }

        .input:focus {
          border-color: var(--primary);
          box-shadow: 0 0 0 4px var(--ring);
        }

        .actions {
          margin-top: 24px;
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
        }

        .btn-primary {
          background-color: var(--primary);
          color: white;
        }

        .btn-primary:hover {
          transform: translateY(-1px);
          box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .btn-secondary {
          background: transparent;
          color: var(--text-muted);
          margin-top: 12px;
          font-weight: 500;
        }

        .btn-secondary:hover {
          color: var(--text-main);
          background: #f9fafb;
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
        <h2 className="title">Iniciar sesión</h2>

        <form onSubmit={handleLogin}>
          <div className="form-group">
            <label className="label">Correo electrónico</label>
            <input
              className="input"
              type="email"
              placeholder="nombre@ejemplo.com"
              value={email}
              onChange={e => setEmail(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label className="label">Contraseña</label>
            <input
              className="input"
              type="password"
              placeholder="••••••••"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
            />
          </div>

          <div className="actions">
            <button type="submit" className="btn btn-primary">
              Entrar
            </button>
            
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => { setEmail(''); setPassword(''); setMsg(''); }}
            >
              Limpiar campos
            </button>
          </div>
        </form>

        <div className="footer-links">
          <span>¿No tienes cuenta?</span>
          <Link to="/register" className="link">Crear cuenta</Link>
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