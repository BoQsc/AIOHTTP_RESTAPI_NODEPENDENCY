@ECHO OFF
curl -X POST https://localhost:443/t ^
  -H "Content-Type: application/json" ^
  -d "{\"name\": \"John\", \"message\": \"Hello World\"}" ^
  -k
  
PAUSE