
# VIX-Gateway

QUIC-Enabled POSIX: A Fast HTTP/3 Gateway with Seamless FUSE Client

## 📖 Blog Post

Read the full article here:  
👉 https://medium.com/@hardikprl94/quic-enabled-posix-a-fast-http-3-gateway-with-seamless-fuse-client-15a6735cc9db


## Control Server

`vix --server --cert quic_cert.pem --key quic_key.pem`

## Gateway Server

`vix --host 0.0.0.0 --port 9443 --storage ~/vx_data --flat --control-host 10.18.0.2 --control-port 9444 --client-id lakehouse-dev --token dev`

