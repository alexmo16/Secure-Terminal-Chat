winpty openssl req -nodes -newkey rsa:2048 -keyout client-key.key -out req.csr -config ../gei761.conf
winpty openssl ca -config ../gei761.conf -extensions v3_req -in req.csr -out client-cert.cer