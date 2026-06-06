# Search Package

Dark web search engine collection and circuit breaker implementation.

## Circuit Breaker

The circuit breaker (`circuit_breaker.py`) provides resilient, shared state across Uvicorn workers:

- Uses Redis for shared state (keys: `circuit:{engine_name}:failures`, `circuit:{engine_name}:last_success`, `circuit:{engine_name}:state`)
- Falls back to in-memory dict if Redis is unavailable
- Constants: `FAILURE_THRESHOLD = 5`, `OPEN_DURATION_SECONDS = 300`, `HALF_OPEN_TEST_INTERVAL = 60`