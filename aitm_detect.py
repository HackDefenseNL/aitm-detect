import requests
import re
import argparse

GREEN = "\033[92m"
RED = "\033[91m"
ORANGE = "\033[33m"
RESET = "\033[0m"

BANNER = f"""
===============================================
{GREEN}Looking for Anti-AiTM measures? ;) {RESET}
===============================================
"""

def extract_custom_css_url(response_text):
    match = re.search(r'customCssUrl":"(https://[^"]+)', response_text)
    return match.group(1) if match else None

def extract_image_urls(css_content):
    return re.findall(r'url\((.*?)\)', css_content)

def main(url):
    print(BANNER)

    full_url = f"https://login.microsoftonline.com/?whr={url}"
    response = requests.get(full_url)

    if response.status_code == 200:
        print(f"[{GREEN}+{RESET}] {url} domain is valid!")
        custom_css_url = extract_custom_css_url(response.text)

        if custom_css_url:
            css_response = requests.get(custom_css_url)
            
            print(f"[{GREEN}+{RESET}] Custom CSS company branding found! Fetching Custom CSS content from:\n{custom_css_url}")

            if css_response.status_code == 200:
                image_urls = extract_image_urls(css_response.text)

                if image_urls:
                    print(f"[{GREEN}+{RESET}] External (image) URLs found in CSS content, possibly used as anti-AiTM measure(s):")
                    for img_url in image_urls:
                        print(img_url.strip('\'"'))
                else:
                    print(f"[{RED}-{RESET}] No (image) URLs found in the CSS content. Manually review the CSS content!")
                    print(f"[{ORANGE}!{RESET}] Printing company branding custom CSS content:\n{css_response.text}")

            else:
                print(f"[{RED}-{RESET}] Failed to fetch custom CSS content. Status code: {css_response.status_code}")
        else:
            print(f"[{RED}-{RESET}] No 'customCssUrl' found in the response. There is most likely no custom CSS company branding!")
    else:
        print(f"[{RED}-{RESET}] Failed to fetch content. Status code: {response.status_code}")

def domains_from_file(hosts):
    with open(hosts, 'r') as file:
        for line in file:
            domain = line.strip()
            if domain:
                main(domain)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check custom CSS company branding for AiTM measures")
    parser.add_argument('-d','--domain', help="domain to check for company branding CSS files")
    parser.add_argument('-l', '--list', help="file containing a list of domains to check", required=False)
    args = parser.parse_args()

    if args.domain:
        main(args.domain)
    elif args.list:
        domains_from_file(args.list)
    else:
        print("[{RED}-{RESET}] Provide either --domain or --list")