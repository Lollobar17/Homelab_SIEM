## test_sender.nim — Test per src/sender.nim
##
## Nessuno di questi test tocca la rete: 'transport' e 'sleepFn' sono finti,
## iniettati al posto delle versioni reali. Verifichiamo solo la LOGICA di
## retry/backoff, non il comportamento di una vera libreria HTTP.

import std/unittest
import std/strutils
import ../src/models
import ../src/sender

suite "send — successo":
  test "risposta 200 al primo tentativo: nessun retry":
    var callCount = 0
    proc fakeTransport(url, body, token: string): HttpResult =
      inc callCount
      HttpResult(code: 200, body: "ok")

    let cfg = newSenderConfig("http://fake/ingress", maxRetries = 3)
    let res = send(cfg, "{}", transport = fakeTransport,
                    sleepFn = proc(ms: int) = discard)

    check res.isOk == true
    check res.value == 200
    check callCount == 1  # nessun retry necessario

suite "send — errore client (4xx), nessun retry":
  test "401 non autorizzato: fallisce subito, un solo tentativo":
    var callCount = 0
    proc fakeTransport(url, body, token: string): HttpResult =
      inc callCount
      HttpResult(code: 401, body: "unauthorized")

    let cfg = newSenderConfig("http://fake/ingress", maxRetries = 3)
    let res = send(cfg, "{}", transport = fakeTransport,
                    sleepFn = proc(ms: int) = discard)

    check res.isOk == false
    check "401" in res.error
    check callCount == 1  # NIENTE retry su 4xx

suite "send — errore server (5xx), retry con backoff":
  test "500 persistente esaurisce tutti i tentativi (maxRetries + 1 chiamate)":
    var callCount = 0
    proc fakeTransport(url, body, token: string): HttpResult =
      inc callCount
      HttpResult(code: 500, body: "internal error")

    var sleepCalls: seq[int] = @[]
    proc fakeSleep(ms: int) = sleepCalls.add(ms)

    let cfg = newSenderConfig("http://fake/ingress", maxRetries = 3,
                              retryBaseDelayMs = 100)
    let res = send(cfg, "{}", transport = fakeTransport, sleepFn = fakeSleep)

    check res.isOk == false
    check callCount == 4  # tentativo iniziale + 3 retry
    check sleepCalls == @[100, 200, 400]  # backoff esponenziale: 100*2^(n-1)

  test "successo al secondo tentativo dopo un primo 500":
    var callCount = 0
    proc fakeTransport(url, body, token: string): HttpResult =
      inc callCount
      if callCount == 1:
        HttpResult(code: 500, body: "temporary")
      else:
        HttpResult(code: 200, body: "ok")

    let cfg = newSenderConfig("http://fake/ingress", maxRetries = 3,
                              retryBaseDelayMs = 10)
    let res = send(cfg, "{}", transport = fakeTransport,
                    sleepFn = proc(ms: int) = discard)

    check res.isOk == true
    check res.value == 200
    check callCount == 2

suite "send — errore di trasporto (code 0, es. connessione rifiutata)":
  test "code 0 viene trattato come recuperabile (retry), non come 4xx":
    var callCount = 0
    proc fakeTransport(url, body, token: string): HttpResult =
      inc callCount
      HttpResult(code: 0, body: "connection refused")

    let cfg = newSenderConfig("http://fake/ingress", maxRetries = 2,
                              retryBaseDelayMs = 10)
    let res = send(cfg, "{}", transport = fakeTransport,
                    sleepFn = proc(ms: int) = discard)

    check res.isOk == false
    check callCount == 3  # tentativo iniziale + 2 retry, come un 5xx

suite "send — input vuoti":
  test "body vuoto viene comunque inviato (non e' compito di sender.nim validarlo)":
    var receivedBody = ""
    proc fakeTransport(url, body, token: string): HttpResult =
      receivedBody = body
      HttpResult(code: 200, body: "ok")

    let cfg = newSenderConfig("http://fake/ingress")
    let res = send(cfg, "", transport = fakeTransport,
                    sleepFn = proc(ms: int) = discard)

    check res.isOk == true
    check receivedBody == ""

  test "agentToken vuoto viene comunque passato al transport":
    var receivedToken = "non-toccato"
    proc fakeTransport(url, body, token: string): HttpResult =
      receivedToken = token
      HttpResult(code: 200, body: "ok")

    let cfg = newSenderConfig("http://fake/ingress", agentToken = "")
    discard send(cfg, "{}", transport = fakeTransport,
                 sleepFn = proc(ms: int) = discard)

    check receivedToken == ""
