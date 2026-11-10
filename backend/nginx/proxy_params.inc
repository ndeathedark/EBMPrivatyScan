proxy_http_version 1.1;
proxy_set_header Host $host;
# X-Real-IP se sobrescribe con la IP real de la conexión: el cliente no puede falsificarla.
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $remote_addr;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_connect_timeout 10s;
