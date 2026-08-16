## 2025-02-18 - XSS in Streamlit unsafe_allow_html
**Vulnerability:** Streamlit markdown elements using `unsafe_allow_html=True` are vulnerable to Cross-Site Scripting (XSS) when rendering user-controlled inputs (like log fields, IPs, and usernames) without escaping them.
**Learning:** `st.markdown(..., unsafe_allow_html=True)` acts similarly to `dangerouslySetInnerHTML`. Since log ingestion accepts user-supplied log content (e.g., from attackers who might inject malicious scripts into syslog or uploaded CSVs), inserting these strings directly into HTML templates exposes the application to stored XSS.
**Prevention:** Always use `html.escape()` on all user-supplied data variables before interpolating them into HTML strings that are passed to Streamlit with `unsafe_allow_html=True`.
