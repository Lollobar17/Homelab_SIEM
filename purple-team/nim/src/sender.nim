## sender.nim — Invio HTTP del payload di telemetria verso il SIEM ingress.
##
## Responsabilità unica: prendere una stringa JSON già pronta (prodotta da
## telemetry.nim) e consegnarla via HTTP POST, con retry/backoff in caso di
## errore server, senza ritentare su errori client (4xx). Non costruisce
## il payload, non decide cosa inviare.

import std/httpclient
import std/os
import ./models

type
  HttpResult* = object
    code*: int
    body*: string

  Transport* = proc(url, body, token: string): HttpResult
    ## Una proc-come-valore: chiunque implementi questa firma può fare da
    ## "trasporto". In produzione è httpTransport (sotto); nei test è una
    ## funzione finta che restituisce risultati programmati, senza rete.

  SenderConfig* = object
    endpoint*: string
    agentToken*: string
    maxRetries*: int
    retryBaseDelayMs*: int
      ## In produzione: 1000ms, raddoppiati ad ogni tentativo (backoff
      ## esponenziale). Nei test: valori piccoli o sleepFn finta, per non
      ## far durare la suite di test decine di secondi.

proc newSenderConfig*(endpoint: string, agentToken: string = "",
                       maxRetries: int = 3,
                       retryBaseDelayMs: int = 1000): SenderConfig =
  SenderConfig(endpoint: endpoint, agentToken: agentToken,
               maxRetries: maxRetries, retryBaseDelayMs: retryBaseDelayMs)

proc httpTransport*(url, body, token: string): HttpResult =
  ## Trasporto reale: apre una connessione HTTP effettiva verso il SIEM.
  let client = newHttpClient(timeout = 5000)
  ## `defer` esegue l'istruzione alla USCITA dal blocco proc, qualunque sia
  ## il percorso (successo, errore, return anticipato) — garantisce che la
  ## connessione venga sempre chiusa, come `defer resp.Body.Close()` in Go.
  defer: client.close()
  client.headers = newHttpHeaders({
    "Content-Type": "application/json",
    "X-Agent-Token": token
  })
  try:
    let response = client.post(url, body = body)
    result = HttpResult(code: response.code.int, body: response.body)
  except CatchableError as e:
    ## code = 0 segnala "non ho nemmeno ricevuto una risposta" (errore di
    ## rete/connessione), distinto da un vero status code HTTP.
    result = HttpResult(code: 0, body: "transport error: " & e.msg)

proc send*(config: SenderConfig, body: string,
           transport: Transport = httpTransport,
           sleepFn: proc(ms: int) = os.sleep): Result[int] =
  ## Ritorna Result[int]: in caso di successo, il codice HTTP 2xx ricevuto;
  ## in caso di fallimento, un errore testuale dopo aver esaurito i tentativi.
  ##
  ## Logica di retry, identica a quella del Go agent:
  ##   - 2xx           -> successo immediato
  ##   - 4xx           -> errore non recuperabile, NESSUN retry
  ##   - 5xx / code==0 -> errore recuperabile, retry con backoff esponenziale
  var lastError = ""
  for attempt in 0 .. config.maxRetries:
    if attempt > 0:
      sleepFn(config.retryBaseDelayMs * (1 shl (attempt - 1)))

    let res = transport(config.endpoint, body, config.agentToken)

    if res.code >= 200 and res.code < 300:
      return ok(res.code)
    elif res.code >= 400 and res.code < 500:
      return err[int]("errore client non recuperabile: " & $res.code)
    else:
      lastError = "errore trasporto/server: code=" & $res.code & " body=" & res.body

  err[int]("invio fallito dopo " & $(config.maxRetries + 1) &
           " tentativi: " & lastError)
