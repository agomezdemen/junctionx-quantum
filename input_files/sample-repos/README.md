# Sample repos

Codigo-fonte em Python, Java e Go para pratica de analise estatica (SAST) e
inventario criptografico. Ao contrario do resto do laboratorio
(`auth_service.py`, `PaymentProcessor.java`, Nginx), estes ficheiros nao
correm como servicos — sao apenas codigo para inspecionar, cada um
executavel isoladamente.

```
sample-repos/
  python/   ficheiros .py standalone (python3 ficheiro.py)
  java/     ficheiros .java standalone, sem pacote (javac X.java && java X)
  go/       um modulo Go, um "package main" por subdiretorio (go run ./nome)
```

```sh
# Python
cd python && python3 -m venv .venv && . .venv/bin/activate && pip install -r requirements.txt
python <ficheiro>.py

# Java
cd java && javac <Ficheiro>.java && java <Ficheiro>

# Go
cd go && go run ./<subdiretorio>
```
