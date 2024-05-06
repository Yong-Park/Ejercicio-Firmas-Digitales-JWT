import React, { useState } from 'react';
import axios from 'axios';

function App() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [message, setMessage] = useState('');

  const register = async () => {
    const res = await axios.post('http://localhost:5000/register', { username, password });
    setMessage(res.data.message);
  };

  const login = async () => {
    try {
      const res = await axios.post('http://localhost:5000/login', {}, {
        auth: {
          username: username,
          password: password
        }
      });
      localStorage.setItem('token', res.data.token);
      console.log('token savesd: ',res.data.token)
      setMessage('Inicio de sesión exitoso!');
    } catch (error) {
      if (error.response && error.response.status === 401) {
        setMessage('Nombre de usuario o contraseña incorrectos');
      } else {
        setMessage('Ocurrió un error al intentar iniciar sesión');
      }
    }
  };
    

  const accessProtected = async () => {
    const token = localStorage.getItem('token');
    console.log('token: ',token)
    const res = await axios.get('http://localhost:5000/protected', { headers: { 'x-access-token': token } });
    setMessage(JSON.stringify(res.data, null, 2));
  };

  return (
    <div className="App">
      <input type="text" placeholder="Nombre de usuario" onChange={e => setUsername(e.target.value)} />
      <input type="password" placeholder="Contraseña" onChange={e => setPassword(e.target.value)} />
      <button onClick={register}>Registrarse</button>
      <button onClick={login}>Iniciar sesión</button>
      <button onClick={accessProtected}>Acceder a recurso protegido</button>
      <p>{message}</p>
    </div>
  );
}

export default App;
