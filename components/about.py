"""
Creator Profile / About Me Component (Built By Advaith K.)
"""

import base64
import os
import textwrap
import streamlit as st


def image_to_data_uri(image_path):
    """Converts image file to base64 data URI with fallback SVG if file is missing."""
    if image_path and os.path.exists(image_path):
        try:
            with open(image_path, "rb") as image_file:
                encoded_image = base64.b64encode(image_file.read()).decode("utf-8")
            return f"data:image/jpeg;base64,{encoded_image}"
        except Exception:
            pass

    # Clean SVG fallback avatar
    return "data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='120' height='120' viewBox='0 0 120 120'><circle cx='60' cy='60' r='60' fill='%23161b22'/><circle cx='60' cy='45' r='22' fill='%2358a6ff'/><path d='M25 100c0-20 16-35 35-35s35 15 35 35z' fill='%2358a6ff'/></svg>"


def render_built_by_page(profile_image_path=None):
    """Render the Built By creator profile page."""
    if profile_image_path is None:
        profile_image_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "assets", "profile.jpg")

    profile_image_uri = image_to_data_uri(profile_image_path)

    st.html(textwrap.dedent(f"""
    <div style="max-width: 780px; margin: 15px auto 45px auto; padding: 0 10px;">
        <!-- Header Badge -->
        <div style="text-align: center; margin-bottom: 25px;">
            <span style="font-size: 11px; font-weight: 700; text-transform: uppercase; color: #818cf8; background: rgba(99, 102, 241, 0.12); border: 1px solid rgba(99, 102, 241, 0.25); padding: 6px 16px; border-radius: 20px; letter-spacing: 0.12em; font-family: 'Inter', sans-serif;">
                👨‍💻 Creator Profile
            </span>
        </div>

        <!-- Main Glass Card -->
        <div style="background: #161B22; border: 1px solid #30363D; border-radius: 12px; text-align: center; padding: 45px 35px; box-shadow: 0 12px 40px rgba(0, 0, 0, 0.5);">
            <!-- Profile Avatar -->
            <img src="{profile_image_uri}" alt="Profile photo" style="width: 120px; height: 120px; border-radius: 50%; object-fit: cover; object-position: center; display: block; box-shadow: 0 12px 35px rgba(99, 102, 241, 0.4), 0 0 25px rgba(6, 182, 212, 0.3); border: 3px solid rgba(255, 255, 255, 0.18); margin: 0 auto 24px auto;">

            <!-- Name & Title -->
            <h1 style="font-family: 'Inter', sans-serif; font-size: 2.2rem; font-weight: 700; color: #f8fafc; margin: 0 0 10px 0; letter-spacing: -0.02em;">
                Advaith K.
            </h1>

            <div style="font-size: 1.1rem; font-weight: 600; color: #38bdf8; margin-bottom: 12px; font-family: 'Inter', sans-serif;">
                🎓 B.Tech Cyber Security Student
            </div>

            <div style="font-size: 1rem; color: #cbd5e1; margin-bottom: 8px; font-family: 'Inter', sans-serif;">
                🤖 Passionate about Artificial Intelligence & Cybersecurity
            </div>

            <div style="font-size: 0.95rem; color: #94a3b8; margin-bottom: 24px; font-family: 'Inter', sans-serif; font-weight: 500;">
                💻 Python • Streamlit • Git
            </div>

            <!-- Skill Badges -->
            <div style="display: flex; flex-wrap: wrap; justify-content: center; gap: 10px; margin-bottom: 32px;">
                <span style="background: rgba(99, 102, 241, 0.12); border: 1px solid rgba(99, 102, 241, 0.3); color: #a5b4fc; padding: 6px 16px; border-radius: 20px; font-size: 13px; font-weight: 600; font-family: 'Inter', sans-serif; display: inline-flex; align-items: center; gap: 6px;">
                    🐍 Python
                </span>
                <span style="background: rgba(6, 182, 212, 0.12); border: 1px solid rgba(6, 182, 212, 0.3); color: #67e8f9; padding: 6px 16px; border-radius: 20px; font-size: 13px; font-weight: 600; font-family: 'Inter', sans-serif; display: inline-flex; align-items: center; gap: 6px;">
                    ⚡ Streamlit
                </span>
                <span style="background: rgba(168, 85, 247, 0.12); border: 1px solid rgba(168, 85, 247, 0.3); color: #c084fc; padding: 6px 16px; border-radius: 20px; font-size: 13px; font-weight: 600; font-family: 'Inter', sans-serif; display: inline-flex; align-items: center; gap: 6px;">
                    📦 Git
                </span>
                <span style="background: rgba(56, 189, 248, 0.12); border: 1px solid rgba(56, 189, 248, 0.3); color: #7dd3fc; padding: 6px 16px; border-radius: 20px; font-size: 13px; font-weight: 600; font-family: 'Inter', sans-serif; display: inline-flex; align-items: center; gap: 6px;">
                    🤖 AI
                </span>
                <span style="background: rgba(52, 211, 153, 0.12); border: 1px solid rgba(52, 211, 153, 0.3); color: #6ee7b7; padding: 6px 16px; border-radius: 20px; font-size: 13px; font-weight: 600; font-family: 'Inter', sans-serif; display: inline-flex; align-items: center; gap: 6px;">
                    🛡️ Cybersecurity
                </span>
            </div>

            <!-- Personal Project Quote Card -->
            <div style="background: rgba(13, 17, 23, 0.6); border: 1px solid #30363D; border-radius: 12px; padding: 24px 28px; text-align: left; margin-bottom: 35px;">
                <p style="color: #cbd5e1; font-size: 15px; line-height: 1.75; font-family: 'Inter', sans-serif; margin: 0;">
                    💬 This project was developed to explore how AI can be applied to real-world cybersecurity challenges. It reflects my focus on building practical, user-oriented AI solutions while strengthening my skills in software development and machine learning.
                </p>
            </div>

            <!-- Connect with Me Section -->
            <div style="border-top: 1px solid #30363D; padding-top: 28px;">
                <h3 style="font-family: 'Inter', sans-serif; font-size: 1.25rem; font-weight: 700; color: #f8fafc; margin: 0 0 20px 0;">
                    🌐 Connect with Me
                </h3>
                <div style="display: flex; justify-content: center; gap: 16px; flex-wrap: wrap;">
                    <a href="https://github.com/advaith-k-0911/AI-ATS-Analyzer" target="_blank" style="text-decoration: none;">
                        <div style="display: flex; align-items: center; gap: 10px; padding: 12px 24px; background: #21262D; border: 1px solid #30363D; border-radius: 8px; color: #f8fafc; font-family: 'Inter', sans-serif; font-weight: 600; font-size: 14.5px; transition: all 0.2s ease;">
                            <span style="font-size: 18px;">🐙</span> GitHub
                        </div>
                    </a>
                    <a href="https://www.linkedin.com/in/advaith-k-21jul2006/" target="_blank" style="text-decoration: none;">
                        <div style="display: flex; align-items: center; gap: 10px; padding: 12px 24px; background: rgba(88,166,255,0.15); border: 1px solid rgba(88,166,255,0.4); border-radius: 8px; color: #58a6ff; font-family: 'Inter', sans-serif; font-weight: 600; font-size: 14.5px; transition: all 0.2s ease;">
                            <span style="font-size: 18px;">💼</span> LinkedIn
                        </div>
                    </a>
                </div>
            </div>
        </div>
    </div>
    """).strip())
