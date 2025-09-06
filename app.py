import streamlit as st
import joblib
import pandas as pd
import re
from urllib.parse import urlparse
import altair as alt

# --- 모델 및 데이터 로드 ---
try:
    # 학습된 모델 파일 로드
    model = joblib.load('phishing_model.pkl')
    
    # 예시를 위한 가상의 데이터셋 로드 (실제 배포 시에는 Kaggle 데이터셋을 사용)
    # 실제로는 'phishing_website_detection.csv'를 로드해야 합니다.
    data = {
        'url_length': [50, 25, 60, 30, 75, 40],
        'hostname_length': [30, 15, 40, 20, 55, 25],
        'ip_in_url': [0, 0, 0, 0, 1, 0],
        'https_in_url': [1, 1, 0, 1, 0, 1],
        'special_chars': [3, 1, 5, 2, 7, 3],
        'num_dots': [2, 1, 4, 2, 5, 3],
        'at_sign': [0, 0, 1, 0, 1, 0],
        'hyphen_in_url': [1, 0, 1, 0, 1, 0],
        'hyphen_in_subdomain': [0, 0, 0, 0, 1, 0],
        'long_domain': [1, 0, 1, 0, 1, 0],
        'label': [0, 0, 1, 0, 1, 0]  # 0: 안전, 1: 피싱
    }
    df = pd.DataFrame(data)
    
except FileNotFoundError:
    st.error("모델 파일을 찾을 수 없습니다. 'phishing_model.pkl' 파일이 프로젝트 루트 디렉터리에 있는지 확인해주세요.")
    st.stop()

# --- URL 특징 추출 함수 ---
def extract_features(url):
    features = {}
    parsed_url = urlparse(url)

    features['url_length'] = len(url)
    features['hostname_length'] = len(parsed_url.netloc)
    features['ip_in_url'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', parsed_url.netloc) else 0
    features['https_in_url'] = 1 if parsed_url.scheme == 'https' else 0
    features['special_chars'] = len(re.findall(r'[@?-_&=%]', url))
    features['num_dots'] = url.count('.')
    features['at_sign'] = 1 if '@' in url else 0
    features['hyphen_in_url'] = 1 if '-' in url else 0
    
    parts = parsed_url.netloc.split('.')
    features['hyphen_in_subdomain'] = 1 if any(part.startswith('-') or part.endswith('-') for part in parts) else 0
    
    domain = parsed_url.netloc
    features['long_domain'] = 1 if len(domain.split('.')[0]) > 30 else 0
    
    return pd.DataFrame([features])

# --- 스트림릿 애플리케이션 레이아웃 ---
st.set_page_config(
    page_title="피싱 웹사이트 탐지기",
    page_icon="🎣"
)

st.title("🎣 피싱 웹사이트 탐지기")
st.markdown("### URL을 입력하여 피싱 웹사이트인지 확인해보세요.")

with st.expander("사용법", expanded=False):
    st.markdown("""
    1. 아래 입력창에 의심스러운 웹사이트 **URL**을 붙여넣으세요.
    2. **'탐지하기'** 버튼을 클릭하세요.
    3. 이 앱은 머신러닝 모델의 예측 결과를 제공하며, 완전히 정확하지 않을 수 있습니다. 항상 주의하세요.
    """)

# URL 입력 필드
user_input = st.text_input("URL 입력", "https://")

# 탐지 버튼
if st.button("탐지하기", type="primary"):
    if not user_input or user_input == "https://":
        st.warning("URL을 입력해주세요.")
    else:
        with st.spinner("분석 중..."):
            try:
                # 특징 추출 및 예측
                features_df = extract_features(user_input)
                prediction = model.predict(features_df)
                prediction_proba = model.predict_proba(features_df)

                if prediction[0] == 1:
                    st.error("⚠️ **위험!** 이 URL은 **피싱 웹사이트**일 가능성이 높습니다.")
                    st.write("확률:", f"**{prediction_proba[0][1]*100:.2f}%**")
                else:
                    st.success("✅ **안전!** 이 URL은 **안전한 사이트**로 탐지되었습니다.")
                    st.write("확률:", f"**{prediction_proba[0][0]*100:.2f}%**")

                # --- 모델 분석 및 시각화 섹션 ---
                st.markdown("---")
                st.subheader("모델 분석")
                st.markdown("모델이 URL을 어떻게 분석했는지 주요 특징을 보여드립니다.")
                
                # 1. 특징별 중요도 막대 그래프
                if hasattr(model, 'feature_importances_'):
                    feature_importances = pd.DataFrame(model.feature_importances_, 
                                                       index=features_df.columns, 
                                                       columns=['importance']).sort_values('importance', ascending=False)
                    st.write("**주요 특징 중요도**")
                    st.bar_chart(feature_importances)
                    st.markdown("높은 막대일수록 모델이 판별에 중요하게 사용한 특징입니다.")

                # 2. URL 길이 분포 비교
                st.write("**URL 길이 분포**")
                # 실제 데이터셋의 URL 길이를 사용해야 정확한 그래프를 만들 수 있습니다.
                # 아래는 가상의 데이터로 만든 예시입니다.
                length_df = pd.DataFrame({
                    'URL 길이': [len(url) for url in df.index],  # 실제로는 df['url_column'] 사용
                    '유형': df['label'].apply(lambda x: '피싱' if x == 1 else '안전')
                })
                
                # 가상의 데이터로 그래프 생성 (실제 데이터셋의 URL 길이를 사용)
                phishing_lengths = [60, 75, 80, 95]
                safe_lengths = [25, 30, 40, 55]

                combined_data = pd.DataFrame({
                    'URL 길이': phishing_lengths + safe_lengths,
                    '유형': ['피싱'] * len(phishing_lengths) + ['안전'] * len(safe_lengths)
                })

                chart = alt.Chart(combined_data).mark_bar(opacity=0.7).encode(
                    x=alt.X("URL 길이", bin=alt.Bin(maxbins=20), title="URL 길이"),
                    y=alt.Y("count()", title="빈도수"),
                    color='유형'
                ).properties(
                    width=600,
                    height=300
                )
                st.altair_chart(chart)
                st.markdown("일반적으로 피싱 사이트의 URL 길이가 더 긴 경향이 있습니다.")

            except Exception as e:
                st.error(f"오류가 발생했습니다: {e}")
                st.info("올바른 URL 형식을 입력했는지 확인해주세요.")