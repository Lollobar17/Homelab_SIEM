version       = "0.1.0"
author        = "Lorenzo"
description   = "Laboratorio didattico Nim per il Purple Team/SIEM lab (Homelab_SIEM)"
license       = "MIT"
srcDir        = "src"
bin           = @["main"]

requires "nim >= 1.6.0"
# Nessuna dipendenza esterna: tutto il laboratorio usa solo la libreria
# standard di Nim (std/json, std/httpclient, std/unittest, ...).

task test, "Compila ed esegue l'intera suite di test del laboratorio":
  # I binari fixture per artifact_analysis NON sono committati in git
  # (sono artefatti compilati, platform-specific): vengono ricompilati qui
  # ad ogni esecuzione, in modo che il modulo possa analizzarli davvero.
  exec "nim c -d:release --hints:off tests/fixtures/plaintext_sample.nim"
  exec "nim c -d:release --hints:off tests/fixtures/obfuscated_sample.nim"

  exec "nim c -r --hints:off tests/test_models.nim"
  exec "nim c -r --hints:off tests/test_telemetry.nim"
  exec "nim c -r --hints:off tests/test_sender.nim"
  exec "nim c -r --hints:off tests/test_scenarios.nim"
  exec "nim c -r --hints:off tests/test_transform_lab.nim"
  exec "nim c -r --hints:off tests/test_artifact_analysis.nim"
  exec "nim c -r --hints:off tests/test_system_event_lab.nim"
  exec "nim c -r --hints:off tests/test_behavior_lab.nim"
  exec "nim c -r --hints:off tests/test_correlation_lab.nim"
  exec "nim c -r --hints:off tests/test_signal_coverage.nim"
