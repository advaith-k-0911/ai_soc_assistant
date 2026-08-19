## 2024-05-18 - [XSS] Cross-Site Scripting via Streamlit unsafe_allow_html
**Vulnerability:** Unsanitized user inputs (`alert['username']`, `alert['affected_asset']`, etc.) were directly interpolated into HTML strings and rendered in the UI using `st.markdown(unsafe_allow_html=True)`.
**Learning:** Streamlit applications often rely on `unsafe_allow_html=True` for custom UI layouts, making them susceptible to XSS if the data rendered within those custom elements originates from external or untrusted sources (like log files).
**Prevention:** Always use `html.escape(str(variable))` at the UI rendering layer before injecting dynamic variables into HTML strings destined for `st.markdown(unsafe_allow_html=True)`.
