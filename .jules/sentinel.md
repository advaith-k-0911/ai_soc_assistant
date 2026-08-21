## 2024-05-24 - [XSS in Streamlit Markdown rendering]
**Vulnerability:** Cross-Site Scripting (XSS) vulnerability due to user-controlled inputs (like IP, username) being directly interpolated into `st.markdown(..., unsafe_allow_html=True)`.
**Learning:** In this Streamlit application, XSS protection (HTML escaping) must be implemented strictly at the UI rendering layer before interpolating data into `st.markdown(unsafe_allow_html=True)`.
**Prevention:** Always use `html.escape(str(input))` on any user-controlled input before passing it to `st.markdown` when `unsafe_allow_html=True` is enabled.
