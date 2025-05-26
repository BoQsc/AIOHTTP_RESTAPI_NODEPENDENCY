@ECHO OFF
curl -X POST https://localhost:443/ ^
  -H "Content-Type: application/json" ^
  -d "{\"name\": \"John\", \"message\": \"Hello World\"}" ^
  -k
  
PAUSE