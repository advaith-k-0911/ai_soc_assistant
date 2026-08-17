## 2023-10-27 - Streamlit unsafe_allow_html XSS
**Vulnerability:** XSS through Log Injection rendered via `st.markdown(unsafe_allow_html=True)`.
**Learning:** In a data pipeline, attempting to sanitize or escape HTML directly in Pandas DataFrames at the ingestion/normalization layer corrupts data for other services (e.g. PDF exports, AI prompts) and introduces subtle type bugs. XSS mitigation must be isolated strictly to the UI rendering layer where `unsafe_allow_html=True` is used.
**Prevention:** Only use `html.escape()` immediately before interpolating user-controlled variables into raw HTML strings within UI components.
