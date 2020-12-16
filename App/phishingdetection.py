# 1: Safe
# 0: Suspicious
# -1: Phishing

from bs4 import BeautifulSoup
import urllib3
import bs4
import re
import socket
import whois
from datetime import datetime
import time
import requests
from googlesearch import search

import joblib
import os
import sys
import numpy as np

# The below file conststs of necessary patterns such as the url shortners
from patterns import *

# The below file is the location of the classifier
CLASSIFIER_LOCATION = os.path.join(os.getcwd(), 'random_forest.pkl')


def checkHTTPTokenPresence(url):
    '''
    The absence of HTTP/HTTPS token at the start of the URL is often used
    to mask the phishing website as, "https-www-google.com"
    '''
    match = re.search(http_https, url)
    if match and match.start() == 0:
        url = url[match.end():]
    match = re.search('http|https', url)
    return -1 if match else 1


def checkIPAddressPresent(url):
    '''
    The given site must have a IPv4 and IPv6 address. The absence of any one
    of these is a possible sign of phishing.
    '''
    ip_address_pattern = ipv4_pattern + "|" + ipv6_pattern
    match = re.search(ip_address_pattern, url)
    return -1 if match else 1


def measureURLLength(url):
    '''
    To hide the true URL, the length of the url is often large so depending
    on the length of the url, we can check if it is phishing.
    '''
    if len(url) < 54:
        return 1
    if 54 <= len(url) <= 75:
        return 0
    return -1


def checkURLShorteningPresence(url):
    '''
    If the url makes use of a URL shortning service, it can be a phishing
    website.
    '''
    match = re.search(shortening_services, url)
    return -1 if match else 1


def checkAtSymbolPresence(url):
    '''
    The presence of certain symbols is also a seen as a sign of phishing
    website, "@" being one of the more frequently appearing one
    '''
    match = re.search('@', url)
    return -1 if match else 1


def checkPrefixSuffixPresence(domain):
    '''
    Similar to "@", "-" is often seen in the phishing website URL
    '''
    match = re.search('-', domain)

    return -1 if match else 1


def checkDoubleSlashRedirectingPresence(url):
    '''

    The presence of "//" is a sign of redirection, a technique to hide the
    true destination. We recursively try finding the "//" in the URLs besides
    the one in "http://" and "https://"
    '''
    last_double_slash = url.rfind('//')
    return -1 if last_double_slash > 6 else 1


def checkSubDomainPresence(url):
    '''
    The more the number of sub-domains, the more likely the website is a

    phishing website.

    '''

    if checkIPAddressPresent(url) == -1:

        match = re.search(

            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'

            '([01]?\\d\\d?|2[0-4]\\d|25[0-5]))|(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
            url)
        pos = match.end()
        url = url[pos:]
    num_dots = [x.start() for x in re.finditer(r'\.', url)]
    if len(num_dots) <= 3:
        return 1
    elif len(num_dots) == 4:
        return 0
    else:
        return -1


def getDomainRegistrationLength(domain):
    '''
    It has been observed that phishing websites tend to have short
    registration lengths. Hence, older the site, less likely for it
    to be a phishing website.
    '''
    expiration_date = domain.expiration_date
    today = time.strftime('%Y-%m-%d')
    today = datetime.strptime(today, '%Y-%m-%d')

    registration_length = 0
    if expiration_date:
        # If the expiration date truly exists
        registration_length = abs((expiration_date - today).days)
    return -1 if registration_length / 365 <= 1 else 1


def getAgeOfDomain(domain):
    '''
    Phishing website tend to short registration length but also
    have a short age of domain.
    '''
    creation_date = domain.creation_date
    expiration_date = domain.expiration_date
    ageofdomain = 0
    if expiration_date:
        ageofdomain = abs((expiration_date - creation_date).days)
    return -1 if ageofdomain / 30 < 6 else 1


def investigateFavicon(wiki, soup, domain):
    '''
    Presence of favicon loaded from an external site, may be used to
    mask the phishing attempt.
    '''
    for head in soup.find_all('head'):
        for head.link in soup.find_all('link', href=True):
            dots = [x.start() for x in re.finditer(r'\.', head.link['href'])]
            return 1 if wiki in head.link['href'] or len(dots) == 1 or domain in head.link['href'] else -1
    return 1


def investigateRequestUrl(wiki, soup, domain):
    '''
    When the website is loaded, we need the resources to be loaded
    from the same website and not from else where. Like Favicon, this
    is often done to mask the phishing website
    '''
    i = 0
    success = 0
    for img in soup.find_all('img', src=True):
        dots = [x.start() for x in re.finditer(r'\.', img['src'])]
        if wiki in img['src'] or domain in img['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for audio in soup.find_all('audio', src=True):
        dots = [x.start() for x in re.finditer(r'\.', audio['src'])]
        if wiki in audio['src'] or domain in audio['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for embed in soup.find_all('embed', src=True):
        dots = [x.start() for x in re.finditer(r'\.', embed['src'])]
        if wiki in embed['src'] or domain in embed['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for i_frame in soup.find_all('i_frame', src=True):
        dots = [x.start() for x in re.finditer(r'\.', i_frame['src'])]
        if wiki in i_frame['src'] or domain in i_frame['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    try:
        percentage = success / float(i) * 100
    except Exception:
        return 1

    if percentage < 22.0:
        return 1
    elif 22.0 <= percentage < 61.0:
        return 0
    else:
        return -1


def investigateAnchorTag(wiki, soup, domain):
    '''
    Even in the anchor tags, there could be references to an external site,
    and in such cases, the website can be treated as a phishing website
    '''
    i = 0
    unsafe = 0
    for a in soup.find_all('a', href=True):
        if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (
                wiki in a['href'] or domain in a['href']):
            unsafe = unsafe + 1
        i = i + 1
    try:
        percentage = unsafe / float(i) * 100
    except Exception:
        return 1
    if percentage < 31.0:
        return 1
    elif 31.0 <= percentage < 67.0:
        return 0
    else:
        return -1


def investigateLinksInTags(wiki, soup, domain):
    '''
    Finally, it is expected that even the link tags do not acess external
    websites since this is another method as discussed previously to mask
    the phishing attempt
    '''
    i = 0
    success = 0
    for link in soup.find_all('link', href=True):
        dots = [x.start() for x in re.finditer(r'\.', link['href'])]
        if wiki in link['href'] or domain in link['href'] or len(dots) == 1:
            success = success + 1
        i = i + 1

    for script in soup.find_all('script', src=True):
        dots = [x.start() for x in re.finditer(r'\.', script['src'])]
        if wiki in script['src'] or domain in script['src'] or len(dots) == 1:
            success = success + 1
        i = i + 1
    try:
        percentage = success / float(i) * 100
    except Exception:
        return 1

    if percentage < 17.0:
        return 1
    elif 17.0 <= percentage < 81.0:
        return 0
    else:
        return -1


def investigateSFH(wiki, soup, domain):
    '''
    Quite often this feature may not seem relevant but it is commonly
    found that phishing websites tend to have empty entries in the
    "action" parameter of the form.
    '''
    for form in soup.find_all('form', action=True):
        if form['action'] == "" or form['action'] == "about:blank":
            return -1
        elif wiki not in form['action'] and domain not in form['action']:
            return 0
        else:
            return 1
    return 1


def checkEmailSubmission(soup):
    '''
    Presence of a hidden mail function, submitting the information
    entered in the form can be considering as a phishing attempt
    '''
    for form in soup.find_all('form', action=True):
        return -1 if "mailto:" in form['action'] else 1
    # In case there is no form in the soup, then it is safe to return 1.
    return 1


def checkAbnormalURL(domain, url):
    hostname = domain.name
    match = re.search(hostname, url)
    return 1 if match else -1


def checkIframePresence(soup):
    '''
    Presence of iframe is often a sign of phishing website leveraging the
    property of iframe
    '''
    for i_frame in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
        if i_frame['width'] == "0" or i_frame['height'] == "0" or i_frame['frameBorder'] == "0":
            return -1
    # If none of the iframes have a width or height of zero or a frameBorder of size 0, then it is safe to return 1.
    return 1


def measureWebTraffic(url):
    '''
    Web traffic is calculated for legitimate websites, the absence of it
    is a sign of phishing website
    '''
    try:
        rank = \
            bs4.BeautifulSoup(urllib3.request("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find(
                "REACH")['RANK']
    except TypeError:
        return -1
    rank = int(rank)
    return 1 if rank < 100000 else 0


def getGoogleIndex(url):
    '''
    Since phishing websites are online for very short period, then such
    websites do not appear on the Google Index
    '''
    site = search(url, 5)
    return 1 if site else -1


def getStatisticalReport(url, hostname):
    '''
    Several parties create reports of the popular phishing webistes, if
    the given URL matches with any in the report, the site would be a phishing
    website
    '''
    try:
        ip_address = socket.gethostbyname(hostname)
    except Exception:
        return -1

    url_match = re.search(
        r'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
    ip_match = re.search(
        '146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
        '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
        '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
        '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
        '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
        '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42',
        ip_address)
    if url_match or ip_match:
        return -1
    else:
        return 1


def get_hostname_from_url(url):
    '''
    Get the root hostname for other purposes
    '''
    hostname = url
    # TODO: Put this pattern in patterns.py as something like - get_hostname_pattern.
    pattern = "https://|http://|www.|https://www.|http://www."
    pre_pattern_match = re.search(pattern, hostname)

    if pre_pattern_match:
        hostname = hostname[pre_pattern_match.end():]
        post_pattern_match = re.search("/", hostname)
        if post_pattern_match:
            hostname = hostname[:post_pattern_match.start()]

    return hostname


def getFeatures(url):
    '''
    The main driver function to get the features present in
    the URL. Most important condition is that the URL should
    necessarily have the scheme (http/https) and complete
    netloc (i.e. with "www")
    '''

    # Get the HTML content for the website
    try:
        soup_string = requests.get(url).content
    except Exception:
        return [-1] * 22

    soup = BeautifulSoup(soup_string, 'html.parser')

    # Gathering the features
    status = []
    hostname = get_hostname_from_url(url)

    # Note: The order of the features is needed to be so
    # as this is the order of the features in the dataset
    status.append(checkIPAddressPresent(url))

    status.append(measureURLLength(url))

    status.append(checkURLShorteningPresence(url))

    status.append(checkAtSymbolPresence(url))

    status.append(checkDoubleSlashRedirectingPresence(url))

    status.append(checkPrefixSuffixPresence(hostname))

    status.append(checkSubDomainPresence(url))

    dns = 1
    try:
        domain = whois.query(hostname)
    except Exception:
        dns = -1

    status.append(-1 if dns == -1 else getDomainRegistrationLength(domain))

    status.append(investigateFavicon(url, soup, hostname))

    status.append(checkHTTPTokenPresence(url))

    status.append(investigateRequestUrl(url, soup, hostname))

    status.append(investigateAnchorTag(url, soup, hostname))

    status.append(investigateLinksInTags(url, soup, hostname))

    status.append(investigateSFH(url, soup, hostname))

    status.append(checkEmailSubmission(soup))

    status.append(-1 if dns == -1 else checkAbnormalURL(domain, url))

    status.append(checkIframePresence(soup))

    status.append(-1 if dns == -1 else getAgeOfDomain(domain))

    status.append(dns)

    status.append(measureWebTraffic(soup))

    status.append(getGoogleIndex(url))

    status.append(getStatisticalReport(url, hostname))

    return status


def main():
    '''
    The main driver function, it provides decision on the
    basis of the classification done by the classifier.
    '''
    url = sys.argv[1]

    if not (url.startswith("https://") or url.startswith("http://")):
        if url.startswith("www."):
            url = "https://" + url
        else:
            url = "https://www." + url

    features_test = getFeatures(url)

    # Due to updates to scikit-learn, we now need a
    # 2D array as a parameter to the predict function
    features_test = np.array(features_test).reshape((1, -1))

    clf = joblib.load(CLASSIFIER_LOCATION)

    prediction = int(clf.predict(features_test)[0])

    # 1: Safe
    # 0: Suspicious
    # -1: Phishing

    if prediction == 1:
        return 1
    elif prediction == -1 or prediction == 0:
        return -1


if __name__ == '__main__':
    prediction = main()
    if prediction == 1:
        print("SAFE!")
    else:
        print("PHISHING!")
