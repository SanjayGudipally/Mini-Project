# Mini-Project
import streamlit as st
import requests

def check_site_categories(url):
    api_key = 'daf5975188a2ca61093f42b7e730d27f235941145c205cabf036209101628722'
    api_endpoint = f'https://www.virustotal.com/vtapi/v2/url/report?apikey={api_key}&resource={url}'
    
    response = requests.get(api_endpoint)
    result = response.json()

    if result['response_code'] == 1:
        categories_details = [(scan, details['result']) for scan, details in result['scans'].items() if details['result'] in ['malware site', 'phishing site', 'malicious site']]
        categories_count = len(categories_details)
        return categories_count, categories_details
    else:
        return None, None

def main():
    st.title("Check Site Categories")
    url_to_check = st.text_input("Enter URL to check")
    if st.button("Check"):
        if url_to_check:
            categories_count, categories_details = check_site_categories(url_to_check)

            if categories_count is not None:
                st.write(f"Categories for {url_to_check}: {categories_count}")
                if categories_details:
                    st.write("Details:")
                    for scan, category in categories_details:
                        st.write(f"- {scan}: {category}")
            else:
                st.write("No results found for the URL.")

if _name_ == "_main_":
    main()
