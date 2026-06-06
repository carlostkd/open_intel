# i18n — Multilingual Intelligence

Russian, Chinese, and Arabic dark web communities carry high-value intelligence that English-only tooling misses entirely. This module gives the rest of the pipeline language detection, on-the-fly translation back to English, and outbound query expansion across multiple languages.

## Components

- `detect.py` — `detect_language`, `detect_language_batch`, `is_non_english`. Wraps `langdetect` and returns ISO 639-1 codes (`en`, `ru`, `zh`, `ar`, ...). Returns `None` for text under 50 characters or when detection fails — never raises.
- `translate.py` — `translate_to_english`, `translate_batch`. Tries DeepL first (when `DEEPL_API_KEY` is set), then falls back to a Helsinki-NLP/opus-mt local model via `transformers`. Text longer than 2000 characters is split at sentence boundaries, translated piece-by-piece, then rejoined.
- `query_expand.py` — `expand_query`, `get_multilingual_search_terms`. Translates an English query into the configured target languages so `search.py` can fan out across non-English engines. Languages with failed translations are silently skipped.

## Configuration

| Env var | Purpose |
|---|---|
| `DEEPL_API_KEY` | Optional. Enables DeepL as the primary translator. |
| `I18N_LANGUAGES` | Comma-separated ISO 639-1 codes for query expansion. Defaults to `en,ru,zh`. |

If neither DeepL nor `transformers` is available, translation returns `None` and the rest of the pipeline continues with the original text. The module is fully optional — every entry point degrades gracefully.
