# Mesh connector

This package contains a specialized proxy/tunnel server and controllers for the mesh connector.

Currently this is deployed as an extension to the east-west gateway, and should be 
compatible with Istio 1.10+, ASM and MCP. 

Long term, the code will move to upstream Istiod and proxy.

Features:

- SNI proxy extensions to tunnel the request using HTTP/2 Stream, with JWT token authentication. This allows
  sending requests to CloudRun and other HTTP/2 servers without direct mTLS/TCP support.
- Controller to detect the installed istio and create the mesh-env config map.
- WIP: auto-registration code, to improve the UX.
- Experimental: a reverse http/2 proxy, intended for development/debugging, allowing local dev 
  containers to register and receive requests from the mesh.
